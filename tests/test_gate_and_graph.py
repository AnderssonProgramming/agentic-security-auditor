import pytest

from auditor import deploy, graph, report
from auditor.agents import triage
from auditor.agents.validator import new_findings
from auditor.state import Patch, ValidationResult


def _validation(**overrides):
    base = dict(install_ok=True, tests_ok=True, typecheck_ok=True, remaining=[], regressions=[])
    base.update(overrides)
    return ValidationResult(**base)


@pytest.fixture
def blocking_state(make_finding):
    prioritized = triage.prioritize([make_finding(rule_id="crit", cvss=9.8)])
    return {"prioritized": prioritized, "findings": prioritized, "tool_errors": [], "max_fix_attempts": 2}


def test_clean_requires_passing_tests_even_without_findings():
    assert deploy.evaluate_gate({"prioritized": [], "validation": _validation()})[0] == "CLEAN"
    assert deploy.evaluate_gate({"prioritized": [], "validation": _validation(tests_ok=False)})[0] == "BLOCKED"
    assert deploy.evaluate_gate({"prioritized": [], "validation": None})[0] == "BLOCKED"


def test_incomplete_scan_fails_closed():
    verdict, reasons = deploy.evaluate_gate(
        {"prioritized": [], "validation": _validation(), "tool_errors": ["trivy: not installed"]}
    )
    assert verdict == "BLOCKED"
    assert "incomplete scan" in reasons[0]


def test_validated_fix_is_remediated_not_clean(blocking_state):
    state = {**blocking_state, "validation": _validation()}
    assert deploy.evaluate_gate(state)[0] == "REMEDIATED"


def test_regression_or_remaining_findings_block(blocking_state):
    assert deploy.evaluate_gate({**blocking_state, "validation": _validation(regressions=["x"])})[0] == "BLOCKED"
    assert deploy.evaluate_gate({**blocking_state, "validation": _validation(remaining=["x"])})[0] == "BLOCKED"


def test_deploy_refuses_anything_but_clean():
    with pytest.raises(RuntimeError):
        deploy.deploy({"verdict": "REMEDIATED", "deploy_target": "netlify", "repo_path": "."})


def test_netlify_dry_run_builds_prod_command():
    result = deploy.deploy({"verdict": "CLEAN", "deploy_target": "netlify", "repo_path": ".", "dry_run": True, "run_id": "r1"})
    assert result["status"] == "dry-run"
    assert result["command"].startswith("netlify deploy --prod")


def test_routing(blocking_state):
    assert graph.route_after_triage({"prioritized": []}) == "validate"
    assert graph.route_after_triage(blocking_state) == "fix"
    assert graph.route_after_triage({**blocking_state, "max_fix_attempts": 0}) == "gate"

    retry = {**blocking_state, "validation": _validation(tests_ok=False), "fix_attempts": 1}
    assert graph.route_after_validate(retry) == "fix"
    assert graph.route_after_validate({**retry, "fix_attempts": 2}) == "gate"
    assert graph.route_after_validate({**blocking_state, "validation": _validation(), "fix_attempts": 1}) == "gate"

    assert graph.route_after_gate({"verdict": "CLEAN", "deploy_target": "netlify"}) == "deploy"
    assert graph.route_after_gate({"verdict": "CLEAN", "deploy_target": "none"}) == "report"
    assert graph.route_after_gate({"verdict": "REMEDIATED", "deploy_target": "netlify"}) == "report"


def test_new_findings_matches_dependency_aliases(make_finding):
    baseline = [make_finding(rule_id="GHSA-1", package="lodash")]
    same_advisory = make_finding(rule_id="CVE-1", aliases=["GHSA-1"], package="lodash", source="trivy")
    brand_new = make_finding(rule_id="CVE-2", package="lodash")

    assert new_findings(baseline, [same_advisory, brand_new]) == [brand_new]


def test_report_renders_all_sections(blocking_state, tmp_path):
    finding = blocking_state["prioritized"][0]
    state = {
        **blocking_state,
        "repo_path": "demo",
        "run_id": "t1",
        "verdict": "REMEDIATED",
        "verdict_reasons": ["1 blocking finding(s) fixed and validated"],
        "patches": [Patch(finding.fingerprint, "dependency-upgrade", "package.json", "Upgrade pkg", "-a\n+b", True)],
        "validation": _validation(),
    }

    path = report.write(state, str(tmp_path))
    text = open(path, encoding="utf-8").read()

    for heading in ["Executive Summary", "Scan Coverage", "Findings", "Remediation Log", "Validation", "Post-Production Checklist"]:
        assert heading in text
    assert "✅ fixed" in text
    assert (tmp_path / "security-report-t1.json").exists()
