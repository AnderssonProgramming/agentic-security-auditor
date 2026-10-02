"""Triage Officer: de-duplicate, score and prioritise findings.

Scoring is deterministic so the gate is reproducible and auditable. The LLM is only
consulted for SAST ``code`` findings (IDOR, injection) to flag false positives, and
even then it can only *annotate* a finding: it never deletes one, and a finding
marked as a false positive still shows up in the report for a human to confirm.
"""

from __future__ import annotations

from auditor.state import Finding, Severity

# Used when a scanner gives a severity but no CVSS base score.
SEVERITY_TO_CVSS = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

# CWEs that are directly exploitable over HTTP in a typical Express/Next.js backend.
HIGH_IMPACT_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-639", "CWE-22", "CWE-918", "CWE-502", "CWE-1321"}

PRIORITY_BANDS = [(9.0, "P0"), (7.0, "P1"), (4.0, "P2"), (0.1, "P3")]

# Gate policy: anything at these priorities (or any secret) blocks deployment.
BLOCKING_PRIORITIES = {"P0", "P1"}


def base_score(f: Finding) -> float:
    return float(f.cvss) if f.cvss is not None else SEVERITY_TO_CVSS[f.severity]


def risk_score(f: Finding) -> float:
    """CVSS base score adjusted for context the CVSS vector cannot know about."""
    score = base_score(f)
    if f.kind == "secret":
        score = max(score, 9.5)  # a leaked credential is exploitable right now
    if f.kind == "code" and set(f.cwe) & HIGH_IMPACT_CWES:
        score += 0.5  # first-party code on a request path: reachability is near-certain
    if f.kind == "dependency" and f.direct_dependency:
        score += 0.3  # direct deps are more likely to be on a reachable code path
    if f.kind == "dependency" and not f.fixed_version:
        score -= 0.5  # nothing the Fixer can upgrade to; still reported
    return round(max(0.0, min(score, 10.0)), 1)


def priority_for(score: float) -> str:
    for threshold, label in PRIORITY_BANDS:
        if score >= threshold:
            return label
    return "P4"


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge the same advisory reported by several tools, keeping the richest record.

    npm audit reports GHSA ids while trivy reports CVE ids (with the GHSA in
    ``aliases``), so dependency findings are matched on (package, any advisory id).
    """
    merged: dict[str, Finding] = {}
    by_advisory: dict[tuple[str, str], str] = {}
    for f in findings:
        key = f.fingerprint
        if f.kind == "dependency" and f.package:
            ids = {f.rule_id, *f.aliases}
            key = next((by_advisory[(f.package, i)] for i in ids if (f.package, i) in by_advisory), key)
            for i in ids:
                by_advisory[(f.package, i)] = key
        existing = merged.get(key)
        if existing is None:
            merged[key] = f
            continue
        existing.cvss = max(filter(None, [existing.cvss, f.cvss]), default=None)
        existing.fixed_version = existing.fixed_version or f.fixed_version
        existing.cwe = sorted(set(existing.cwe) | set(f.cwe))
        existing.aliases = sorted(set(existing.aliases) | set(f.aliases) | {f.rule_id} - {existing.rule_id})
        existing.direct_dependency = existing.direct_dependency or f.direct_dependency
        if f.source not in existing.source.split("+"):
            existing.source = f"{existing.source}+{f.source}"
    return list(merged.values())


def prioritize(findings: list[Finding]) -> list[Finding]:
    """Score every finding and return the actionable ones, highest risk first."""
    unique = deduplicate(findings)
    for f in unique:
        f.risk_score = risk_score(f)
        f.priority = priority_for(f.risk_score)
    actionable = [f for f in unique if f.priority != "P4"]
    return sorted(actionable, key=lambda f: (-(f.risk_score or 0), f.kind != "secret", f.rule_id))


def blocking(findings: list[Finding]) -> list[Finding]:
    return [
        f
        for f in findings
        if not f.false_positive and (f.kind == "secret" or f.priority in BLOCKING_PRIORITIES)
    ]


def llm_review_code_findings(findings: list[Finding], read_file, llm) -> None:
    """Ask the Triage Officer LLM to confirm SAST hits that need semantic judgement.

    ``read_file(path) -> str`` and ``llm(system, user) -> dict`` are injected so the
    function stays testable and model-agnostic.
    """
    from auditor.prompts import TRIAGE_OFFICER_SYSTEM, triage_user_prompt

    for f in findings:
        if f.kind != "code" or not f.file:
            continue
        try:
            source = read_file(f.file)
        except OSError:
            continue
        verdict = llm(TRIAGE_OFFICER_SYSTEM, triage_user_prompt(f, source))
        f.triage_note = verdict.get("reasoning")
        # Only high-confidence false positives are suppressed from the gate, and they
        # remain visible in the report for human confirmation.
        if verdict.get("is_false_positive") and verdict.get("confidence", 0) >= 0.85:
            f.false_positive = True
