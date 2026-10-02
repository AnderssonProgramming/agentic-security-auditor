"""Patch Developer ("Fixer"): turns prioritised findings into candidate patches.

* Dependency findings are fixed deterministically: direct deps are bumped within the
  same major version; transitive deps are pinned through npm ``overrides``. Major
  upgrades are never applied automatically, they are escalated to a human.
* Code findings are sent to the LLM one at a time. Its answer is a search/replace
  pair that the harness validates against guardrails before touching disk.

Every applied patch carries a snapshot of the files it changed so the Validator can
roll it back precisely.
"""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from auditor.state import Finding, Patch
from auditor.tools.shell import run

MAX_CHANGED_LINES = 40

# Things a security patch must never introduce.
FORBIDDEN_IN_REPLACEMENT = [
    (re.compile(r"\beval\s*\("), "dynamic eval"),
    (re.compile(r"\bnew\s+Function\s*\("), "dynamic Function constructor"),
    (re.compile(r"child_process"), "process execution"),
    (re.compile(r"@ts-(ignore|nocheck|expect-error)"), "type-check suppression"),
    (re.compile(r"eslint-disable"), "lint suppression"),
    (re.compile(r"\bas\s+any\b|:\s*any\b"), "`any` escape hatch"),
    (re.compile(r"\$(queryRaw|executeRaw)Unsafe"), "unsafe raw query API"),
]
# Must not survive in the replacement at all, even if the original already had it.
INTERPOLATED_SQL = re.compile(r"`[^`]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{", re.IGNORECASE)

PROTECTED_PATHS = re.compile(
    r"(^|/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|tsconfig.*\.json|\.github/|.*\.(test|spec)\.[jt]sx?$|__tests__/)"
)


class PatchRejected(ValueError):
    pass


# --------------------------------------------------------------------------- helpers
def _major(version: str | None) -> int | None:
    match = re.search(r"(\d+)\.\d+", version or "")
    return int(match.group(1)) if match else None


def _version_key(version: str | None) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version or "")[:3])


def _unified_diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True), f"a/{path}", f"b/{path}"
        )
    )


def _snapshot(repo: Path, *files: str) -> dict[str, str | None]:
    snap: dict[str, str | None] = {}
    for rel in files:
        p = repo / rel
        snap[rel] = p.read_text(encoding="utf-8") if p.exists() else None
    return snap


def restore(repo: str, patch: Patch) -> None:
    """Undo a patch by restoring the snapshot taken before it was applied."""
    root = Path(repo)
    for rel, content in patch.snapshot.items():
        p = root / rel
        if content is None:
            p.unlink(missing_ok=True)
        else:
            p.write_text(content, encoding="utf-8")
    patch.rolled_back = True


# --------------------------------------------------------------------------- dependencies
def plan_dependency_fix(f: Finding, package_json: dict, fixed_version: str | None = None) -> tuple[str, str] | None:
    """Return (strategy, target) or ``None`` when the fix needs a human (major bump)."""
    fixed_version = fixed_version or f.fixed_version
    if not f.package or not fixed_version:
        return None
    declared = {**package_json.get("dependencies", {}), **package_json.get("devDependencies", {})}
    current = declared.get(f.package) or f.installed_version
    cur_major, fix_major = _major(current), _major(fixed_version)
    if cur_major is not None and fix_major is not None and fix_major > cur_major:
        return None
    if f.package in declared:
        return "dependency-upgrade", f"^{fixed_version}"
    return "dependency-override", f"^{fixed_version}"


def apply_dependency_fix(repo: str, f: Finding, fixed_version: str | None = None) -> Patch | None:
    root = Path(repo)
    pkg_path = root / "package.json"
    package_json = json.loads(pkg_path.read_text(encoding="utf-8"))
    plan = plan_dependency_fix(f, package_json, fixed_version)
    if plan is None:
        return None
    strategy, target = plan
    snap = _snapshot(root, "package.json", "package-lock.json")
    before = snap["package.json"] or ""

    if strategy == "dependency-upgrade":
        section = "dependencies" if f.package in package_json.get("dependencies", {}) else "devDependencies"
        package_json[section][f.package] = target
        description = f"Upgrade direct dependency {f.package} to {target}"
    else:
        package_json.setdefault("overrides", {})[f.package] = target
        description = f"Pin transitive dependency {f.package} to {target} via npm overrides"

    after = json.dumps(package_json, indent=2) + "\n"
    pkg_path.write_text(after, encoding="utf-8")
    # Regenerate the lockfile only; Validator runs the clean install + tests.
    run(["npm", "install", "--package-lock-only", "--ignore-scripts"], cwd=repo, timeout=300)
    return Patch(
        finding_fingerprint=f.fingerprint,
        strategy=strategy,
        file="package.json",
        description=description,
        diff=_unified_diff("package.json", before, after),
        applied=True,
        snapshot=snap,
        rationale=f"{f.rule_id} is fixed in {f.package}@{target.lstrip('^')}; same major version, no API change expected.",
    )


# --------------------------------------------------------------------------- code
def validate_code_patch(f: Finding, source: str, answer: dict) -> str:
    """Check the LLM answer against guardrails and return the patched file content."""
    if not answer.get("can_fix"):
        raise PatchRejected(f"model declined: {answer.get('rationale', 'no reason given')}")
    if not f.file or PROTECTED_PATHS.search(f.file.replace("\\", "/")):
        raise PatchRejected(f"{f.file} is a protected path")
    original, replacement = answer.get("original", ""), answer.get("replacement", "")
    if not original.strip():
        raise PatchRejected("empty `original` snippet")
    count = source.count(original)
    if count != 1:
        raise PatchRejected(f"`original` must match exactly once, matched {count} times")
    for pattern, label in FORBIDDEN_IN_REPLACEMENT:
        if pattern.search(replacement) and not pattern.search(original):
            raise PatchRejected(f"replacement introduces {label}")
    if INTERPOLATED_SQL.search(replacement):
        raise PatchRejected("replacement still builds SQL with interpolated SQL text")
    changed = sum(
        1
        for line in difflib.unified_diff(original.splitlines(), replacement.splitlines(), lineterm="")
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    )
    if changed > MAX_CHANGED_LINES:
        raise PatchRejected(f"patch changes {changed} lines (limit {MAX_CHANGED_LINES})")
    return source.replace(original, replacement, 1)


def apply_code_fix(repo: str, f: Finding, llm, previous_failure: str | None = None) -> Patch:
    from auditor.prompts import PATCH_DEVELOPER_SYSTEM, patch_user_prompt

    root = Path(repo)
    path = root / f.file
    source = path.read_text(encoding="utf-8")
    answer = llm(PATCH_DEVELOPER_SYSTEM, patch_user_prompt(f, source, previous_failure))
    patched = validate_code_patch(f, source, answer)
    snap = {f.file: source}
    path.write_text(patched, encoding="utf-8")
    return Patch(
        finding_fingerprint=f.fingerprint,
        strategy="code-refactor",
        file=f.file,
        description=f"Refactor {f.file}:{f.line} to remediate {f.rule_id}",
        diff=_unified_diff(f.file, source, patched),
        applied=True,
        snapshot=snap,
        rationale=f"{answer.get('rationale', '')} Behaviour change: {answer.get('behaviour_change', 'none')}",
    )


def develop_patches(repo: str, findings: list[Finding], llm=None, previous_failure: str | None = None):
    """Attempt one patch per actionable finding. Returns (patches, escalations)."""
    patches: list[Patch] = []
    escalations: list[str] = []
    upgraded: set[str] = set()
    # A package with several advisories must go to the highest fixed version among them.
    best_fix: dict[str, str] = {}
    for f in findings:
        if f.kind == "dependency" and f.package and f.fixed_version:
            if _version_key(f.fixed_version) > _version_key(best_fix.get(f.package)):
                best_fix[f.package] = f.fixed_version
    for f in findings:
        if f.false_positive:
            continue
        try:
            if f.kind == "dependency":
                if f.package in upgraded:
                    continue  # one bump per package covers all its advisories
                patch = apply_dependency_fix(repo, f, best_fix.get(f.package))
                if patch is None:
                    escalations.append(f"{f.package} {f.rule_id}: no same-major fix available, needs human review")
                    continue
                patches.append(patch)
                upgraded.add(f.package)
            elif f.kind == "code":
                if llm is None:
                    escalations.append(f"{f.file}:{f.line} {f.rule_id}: no LLM configured")
                    continue
                patches.append(apply_code_fix(repo, f, llm, previous_failure))
            else:
                # Secrets must be rotated, not just deleted from HEAD; misconfig needs owner input.
                escalations.append(f"{f.kind} {f.rule_id} in {f.file}: requires manual remediation")
        except PatchRejected as exc:
            escalations.append(f"{f.file or f.package} {f.rule_id}: patch rejected ({exc})")
    return patches, escalations
