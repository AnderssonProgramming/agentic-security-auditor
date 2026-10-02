"""Validator: proves a patch set is safe before the pipeline accepts it.

1. ``npm ci`` from the regenerated lockfile (reproducible install).
2. ``tsc --noEmit`` when the project has a tsconfig (type regressions).
3. ``npm test`` (behaviour regressions).
4. Full re-scan, compared against the baseline:
   * ``remaining``   - actionable findings still present;
   * ``regressions`` - findings that did not exist before patching (e.g. a bumped
     dependency that pulls in a new CVE, or a refactor that adds a new sink).
"""

from __future__ import annotations

import json
from pathlib import Path

from auditor.agents.scanner import scan
from auditor.agents.triage import blocking, prioritize
from auditor.state import Finding, ValidationResult
from auditor.tools.shell import run


def _identities(f: Finding) -> set[str]:
    if f.kind == "dependency":
        return {f"{f.package}|{i}" for i in (f.rule_id, *f.aliases)}
    return {f.fingerprint}


def new_findings(baseline: list[Finding], current: list[Finding]) -> list[Finding]:
    known = set().union(*(_identities(f) for f in baseline)) if baseline else set()
    return [f for f in current if not (_identities(f) & known)]


def _has_script(repo: str, name: str) -> bool:
    try:
        pkg = json.loads((Path(repo) / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    script = pkg.get("scripts", {}).get(name, "")
    return bool(script) and "no test specified" not in script


def validate(
    repo: str, baseline: list[Finding], prioritized: list[Finding] | None = None
) -> tuple[ValidationResult, list[Finding], list[str]]:
    """Install, type-check, test and re-scan.

    When ``prioritized`` is given nothing was patched, so the (expensive) re-scan is
    skipped and those findings are reused: this is the "tests only" path that every
    commit goes through before it can be called CLEAN.
    """
    install = run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=repo, timeout=900)

    typecheck_ok = True
    if install.ok and (Path(repo) / "tsconfig.json").exists():
        typecheck_ok = run(["npx", "--no-install", "tsc", "--noEmit"], cwd=repo, timeout=600).ok

    tests = run(["npm", "test", "--silent"], cwd=repo, timeout=1200) if install.ok else install
    # A project without a test suite cannot prove behaviour preservation: fail closed.
    tests_ok = tests.ok and _has_script(repo, "test")

    if prioritized is None:
        findings, tool_errors = scan(repo)
        current = prioritize(findings)
    else:
        current, tool_errors = prioritized, []
    still_blocking = blocking(current)
    regressions = new_findings(baseline, still_blocking)

    result = ValidationResult(
        install_ok=install.ok,
        tests_ok=tests_ok,
        typecheck_ok=typecheck_ok,
        remaining=[f.fingerprint for f in still_blocking],
        regressions=[f.fingerprint for f in regressions],
        test_output_tail=tests.tail(60) if not tests_ok else "",
    )
    return result, current, tool_errors
