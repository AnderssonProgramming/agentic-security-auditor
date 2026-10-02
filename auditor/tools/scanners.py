"""Scanner skills: run a CLI tool, then normalise its JSON output into ``Finding`` objects.

Parsers are pure functions (``parse_*``) so they can be unit-tested with recorded
fixtures and reused if the raw report is produced elsewhere (e.g. a CI step).
"""

from __future__ import annotations

import json
from pathlib import Path

from auditor.state import Finding, Severity
from auditor.tools.shell import CommandResult, run

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SEMGREP_CONFIGS = ["p/javascript", "p/typescript", "p/nodejsscan", "p/secrets", str(RULES_DIR)]


# --------------------------------------------------------------------------- npm audit
def parse_npm_audit(report: dict) -> list[Finding]:
    """Parse ``npm audit --json`` (npm >= 7, auditReportVersion 2)."""
    findings: list[Finding] = []
    vulns = report.get("vulnerabilities", {})
    for pkg, vuln in vulns.items():
        fix = vuln.get("fixAvailable")
        fixed_version = fix.get("version") if isinstance(fix, dict) and fix.get("name") == pkg else None
        for via in vuln.get("via", []):
            # String entries point at another vulnerable package; that package has its own entry.
            if not isinstance(via, dict):
                continue
            advisory_url = via.get("url", "")
            rule_id = advisory_url.rsplit("/", 1)[-1] if advisory_url else str(via.get("source"))
            cvss = (via.get("cvss") or {}).get("score") or None
            findings.append(
                Finding(
                    source="npm-audit",
                    kind="dependency",
                    rule_id=rule_id,
                    title=via.get("title", "Vulnerable dependency"),
                    severity=Severity.parse(via.get("severity") or vuln.get("severity")),
                    cvss=float(cvss) if cvss else None,
                    cwe=list(via.get("cwe") or []),
                    package=pkg,
                    installed_version=vuln.get("range"),
                    fixed_version=fixed_version,
                    direct_dependency=bool(vuln.get("isDirect")),
                    url=advisory_url or None,
                )
            )
    return findings


def npm_audit(repo: str) -> tuple[list[Finding], CommandResult]:
    # npm audit exits non-zero when vulnerabilities exist; that's not a tool failure.
    result = run(["npm", "audit", "--json", "--omit=dev"], cwd=repo, timeout=300)
    try:
        return parse_npm_audit(json.loads(result.stdout or "{}")), result
    except json.JSONDecodeError:
        return [], result


# --------------------------------------------------------------------------- trivy
def _trivy_cvss(vuln: dict) -> float | None:
    scores = []
    for vendor in ("nvd", "ghsa", "redhat"):
        data = (vuln.get("CVSS") or {}).get(vendor) or {}
        if data.get("V3Score") is not None:
            scores.append(float(data["V3Score"]))
    return max(scores) if scores else None


def parse_trivy(report: dict) -> list[Finding]:
    """Parse ``trivy fs --format json`` (vulnerabilities, secrets and misconfigurations)."""
    findings: list[Finding] = []
    for result in report.get("Results", []) or []:
        target = result.get("Target")
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(
                Finding(
                    source="trivy",
                    kind="dependency",
                    rule_id=v.get("VulnerabilityID", "UNKNOWN"),
                    title=v.get("Title") or v.get("VulnerabilityID", ""),
                    severity=Severity.parse(v.get("Severity")),
                    cvss=_trivy_cvss(v),
                    cwe=list(v.get("CweIDs") or []),
                    package=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=(v.get("FixedVersion") or "").split(",")[0].strip() or None,
                    file=target,
                    url=v.get("PrimaryURL"),
                )
            )
        for s in result.get("Secrets", []) or []:
            findings.append(
                Finding(
                    source="trivy",
                    kind="secret",
                    rule_id=s.get("RuleID", "secret"),
                    title=s.get("Title", "Hard-coded secret"),
                    severity=Severity.parse(s.get("Severity")),
                    file=target,
                    line=s.get("StartLine"),
                    snippet=s.get("Match"),
                )
            )
        for m in result.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            findings.append(
                Finding(
                    source="trivy",
                    kind="config",
                    rule_id=m.get("ID", "misconfig"),
                    title=m.get("Title", "Misconfiguration"),
                    severity=Severity.parse(m.get("Severity")),
                    file=target,
                    url=m.get("PrimaryURL"),
                )
            )
    return findings


def trivy_fs(repo: str) -> tuple[list[Finding], CommandResult]:
    result = run(
        ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", "."],
        cwd=repo,
        timeout=600,
    )
    try:
        return parse_trivy(json.loads(result.stdout or "{}")), result
    except json.JSONDecodeError:
        return [], result


# --------------------------------------------------------------------------- semgrep (SAST)
def parse_semgrep(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for r in report.get("results", []) or []:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        findings.append(
            Finding(
                source="semgrep",
                kind="code",
                rule_id=r.get("check_id", "semgrep"),
                title=extra.get("message", "").strip().splitlines()[0] if extra.get("message") else r.get("check_id", ""),
                severity=Severity.parse(meta.get("impact") or extra.get("severity")),
                cvss=meta.get("cvss"),
                cwe=[c.split(":")[0] for c in cwe],
                file=r.get("path"),
                line=(r.get("start") or {}).get("line"),
                snippet=extra.get("lines"),
            )
        )
    return findings


def semgrep_scan(repo: str) -> tuple[list[Finding], CommandResult]:
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics=off"]
    for cfg in SEMGREP_CONFIGS:
        args += ["--config", cfg]
    result = run(args, cwd=repo, timeout=900)
    try:
        return parse_semgrep(json.loads(result.stdout or "{}")), result
    except json.JSONDecodeError:
        return [], result


# --------------------------------------------------------------------------- gitleaks
def parse_gitleaks(report: list) -> list[Finding]:
    return [
        Finding(
            source="gitleaks",
            kind="secret",
            rule_id=leak.get("RuleID", "secret"),
            title=leak.get("Description", "Hard-coded secret"),
            severity=Severity.CRITICAL,
            file=leak.get("File"),
            line=leak.get("StartLine"),
            # Never store the secret itself in state or reports.
            snippet=f"<redacted {leak.get('RuleID', 'secret')}>",
        )
        for leak in report or []
    ]


def gitleaks_scan(repo: str, report_file: str) -> tuple[list[Finding], CommandResult]:
    result = run(
        ["gitleaks", "detect", "--no-banner", "--redact", "--report-format", "json", "--report-path", report_file],
        cwd=repo,
        timeout=300,
    )
    try:
        return parse_gitleaks(json.loads(Path(report_file).read_text(encoding="utf-8"))), result
    except (OSError, json.JSONDecodeError):
        return [], result


# --------------------------------------------------------------------------- snyk (optional)
def parse_snyk(report: dict) -> list[Finding]:
    findings = []
    for v in report.get("vulnerabilities", []) or []:
        upgrade = [p for p in v.get("upgradePath", []) if p]
        findings.append(
            Finding(
                source="snyk",
                kind="dependency",
                rule_id=(v.get("identifiers", {}).get("CVE") or [v.get("id")])[0],
                title=v.get("title", ""),
                severity=Severity.parse(v.get("severity")),
                cvss=v.get("cvssScore"),
                cwe=list(v.get("identifiers", {}).get("CWE") or []),
                package=v.get("packageName"),
                installed_version=v.get("version"),
                fixed_version=(v.get("fixedIn") or [None])[0],
                direct_dependency=len(v.get("from", [])) <= 2,
                url=f"https://security.snyk.io/vuln/{v.get('id')}",
                triage_note=f"Snyk upgrade path: {' > '.join(map(str, upgrade))}" if upgrade else None,
            )
        )
    return findings


def snyk_test(repo: str) -> tuple[list[Finding], CommandResult]:
    result = run(["snyk", "test", "--json"], cwd=repo, timeout=600)
    try:
        return parse_snyk(json.loads(result.stdout or "{}")), result
    except json.JSONDecodeError:
        return [], result
