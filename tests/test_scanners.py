from auditor.state import Severity
from auditor.tools.scanners import parse_gitleaks, parse_npm_audit, parse_semgrep, parse_trivy


def test_npm_audit_parses_advisories_and_skips_indirect_via(npm_audit_report):
    findings = parse_npm_audit(npm_audit_report)

    assert len(findings) == 1  # "express" only points at body-parser via a string
    f = findings[0]
    assert f.rule_id == "GHSA-35jh-r3h4-6jhm"
    assert f.severity is Severity.HIGH
    assert f.cvss == 7.2
    assert f.fixed_version == "4.17.21"
    assert f.direct_dependency is True


def test_trivy_parses_vulns_secrets_and_takes_first_fixed_version(trivy_report):
    findings = parse_trivy(trivy_report)

    kinds = sorted(f.kind for f in findings)
    assert kinds == ["dependency", "dependency", "secret"]
    qs = next(f for f in findings if f.package == "qs")
    assert qs.fixed_version == "6.7.3"
    lodash = next(f for f in findings if f.package == "lodash")
    assert lodash.aliases == ["GHSA-35jh-r3h4-6jhm"]


def test_semgrep_maps_metadata(semgrep_report):
    [f] = parse_semgrep(semgrep_report)

    assert f.kind == "code"
    assert f.cwe == ["CWE-89"]
    assert f.severity is Severity.CRITICAL
    assert f.line == 14


def test_gitleaks_never_keeps_secret_value():
    [f] = parse_gitleaks([{"RuleID": "github-pat", "Secret": "ghp_realsecret", "File": ".env", "StartLine": 1}])

    assert "ghp_realsecret" not in (f.snippet or "")
    assert f.severity is Severity.CRITICAL
