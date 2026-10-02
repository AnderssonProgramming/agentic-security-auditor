from auditor.agents import triage
from auditor.state import Severity
from auditor.tools.scanners import parse_npm_audit, parse_trivy


def test_same_advisory_from_npm_audit_and_trivy_is_merged(npm_audit_report, trivy_report):
    findings = parse_npm_audit(npm_audit_report) + parse_trivy(trivy_report)

    prioritized = triage.prioritize(findings)

    lodash = [f for f in prioritized if f.package == "lodash"]
    assert len(lodash) == 1
    assert lodash[0].source == "npm-audit+trivy"
    assert "CVE-2021-23337" in lodash[0].aliases


def test_priority_bands_follow_cvss(make_finding):
    critical = make_finding(rule_id="A", cvss=9.8)
    medium = make_finding(rule_id="B", cvss=5.0, package="other")
    info = make_finding(rule_id="C", cvss=None, severity=Severity.INFO, package="x")

    prioritized = triage.prioritize([medium, critical, info])

    assert [f.rule_id for f in prioritized] == ["A", "B"]  # INFO dropped, highest first
    assert prioritized[0].priority == "P0"
    assert prioritized[1].priority == "P2"


def test_secrets_and_first_party_injection_are_boosted(make_finding):
    secret = make_finding(kind="secret", rule_id="aws", cvss=None, severity=Severity.LOW, package=None)
    sqli = make_finding(kind="code", rule_id="sqli", cvss=8.8, cwe=["CWE-89"], package=None, file="a.ts")

    assert triage.risk_score(secret) >= 9.5
    assert triage.risk_score(sqli) == 9.3


def test_dependency_without_fix_is_deprioritized(make_finding):
    assert triage.risk_score(make_finding(cvss=7.2, fixed_version=None)) == 6.7


def test_blocking_policy_ignores_false_positives_and_low_priority(make_finding):
    p0 = make_finding(rule_id="a", cvss=9.9)
    p2 = make_finding(rule_id="b", cvss=5.0, package="b")
    fp = make_finding(kind="code", rule_id="idor", cvss=8.1, package=None, file="r.ts")
    prioritized = triage.prioritize([p0, p2, fp])
    fp.false_positive = True

    assert [f.rule_id for f in triage.blocking(prioritized)] == ["a"]


def test_llm_review_only_suppresses_high_confidence_false_positives(make_finding):
    sure = make_finding(kind="code", rule_id="r1", file="a.ts", package=None)
    unsure = make_finding(kind="code", rule_id="r2", file="b.ts", package=None)
    answers = {
        "a.ts": {"is_false_positive": True, "confidence": 0.95, "reasoning": "bound param on line 3"},
        "b.ts": {"is_false_positive": True, "confidence": 0.6, "reasoning": "maybe"},
    }

    triage.llm_review_code_findings(
        [sure, unsure],
        read_file=lambda path: path,
        llm=lambda system, user: answers["a.ts" if 'path="a.ts"' in user else "b.ts"],
    )

    assert sure.false_positive is True
    assert unsure.false_positive is False
    assert unsure.triage_note == "maybe"
