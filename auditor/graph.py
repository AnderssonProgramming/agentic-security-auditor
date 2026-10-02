"""LangGraph state machine wiring the agents together.

    scan ─► triage ─┬─(nothing blocking)──────────────────────────► gate
                    └─(blocking findings)─► fix ─► validate ─┬─(pass)────────► gate
                                             ▲               ├─(fail, retry)─► fix   (rollback + feedback)
                                             └───────────────┘─(exhausted)───► gate
    gate ─┬─(CLEAN and target configured)─► deploy ─► report ─► END
          └─(REMEDIATED / BLOCKED)──────────────────► report ─► END
"""

from __future__ import annotations

import uuid

from langgraph.graph import END, START, StateGraph

from auditor import deploy as deployer
from auditor import llm as llm_client
from auditor import report
from auditor.agents import patch_developer, scanner, triage, validator
from auditor.prompts import SUBMIT_PATCH_TOOL, SUBMIT_TRIAGE_TOOL
from auditor.state import AuditState
from auditor.tools.shell import run


# --------------------------------------------------------------------------- nodes
def scan_node(state: AuditState) -> dict:
    repo = state["repo_path"]
    findings, errors = scanner.scan(repo)
    sha = run(["git", "rev-parse", "HEAD"], cwd=repo, timeout=30)
    return {
        "baseline_findings": findings,
        "tool_errors": errors,
        "commit_sha": sha.stdout.strip() if sha.ok else state.get("commit_sha", ""),
        "run_id": state.get("run_id") or uuid.uuid4().hex[:8],
    }


def triage_node(state: AuditState) -> dict:
    prioritized = triage.prioritize(state["baseline_findings"])
    if llm_client.available():
        from pathlib import Path

        root = Path(state["repo_path"])
        triage.llm_review_code_findings(
            prioritized,
            read_file=lambda rel: (root / rel).read_text(encoding="utf-8"),
            llm=llm_client.tool_caller(SUBMIT_TRIAGE_TOOL),
        )
    return {"prioritized": prioritized, "findings": prioritized}


def fix_node(state: AuditState) -> dict:
    targets = triage.blocking(state["findings"])
    llm = llm_client.tool_caller(SUBMIT_PATCH_TOOL) if llm_client.available() else None
    patches, escalations = patch_developer.develop_patches(
        state["repo_path"], targets, llm=llm, previous_failure=state.get("fix_feedback")
    )
    return {
        "patches": state.get("patches", []) + patches,
        "escalations": sorted(set(state.get("escalations", []) + escalations)),
        "fix_attempts": state.get("fix_attempts", 0) + 1,
        "fix_feedback": None,
    }


def validate_node(state: AuditState) -> dict:
    repo = state["repo_path"]
    patched = any(p.applied for p in state.get("patches", []))
    result, current, tool_errors = validator.validate(
        repo, state["baseline_findings"], prioritized=None if patched else state["prioritized"]
    )
    update: dict = {"validation": result, "tool_errors": sorted(set(state.get("tool_errors", []) + tool_errors))}
    if result.passed:
        update["findings"] = current
        return update

    # Roll back this attempt's patches (newest first so stacked snapshots unwind correctly).
    for patch in reversed(state.get("patches", [])):
        if patch.applied and not patch.rolled_back:
            patch_developer.restore(repo, patch)
    update["patches"] = state.get("patches", [])
    update["fix_feedback"] = result.test_output_tail or (
        f"{len(result.regressions)} new finding(s) introduced: {', '.join(result.regressions)}"
    )
    return update


def gate_node(state: AuditState) -> dict:
    verdict, reasons = deployer.evaluate_gate(state)
    return {"verdict": verdict, "verdict_reasons": reasons}


def deploy_node(state: AuditState) -> dict:
    return {"deployment": deployer.deploy(state)}


def report_node(state: AuditState) -> dict:
    path = report.write(state, state.get("report_dir", "reports"))
    state = {**state, "report_path": path}
    deployer.write_github_outputs(state)
    return {"report_path": path}


# --------------------------------------------------------------------------- routing
def route_after_triage(state: AuditState) -> str:
    if not triage.blocking(state["prioritized"]):
        return "validate"  # still run install + type check + tests before CLEAN
    return "fix" if state.get("max_fix_attempts", 0) > 0 else "gate"


def route_after_fix(state: AuditState) -> str:
    applied = [p for p in state.get("patches", []) if p.applied and not p.rolled_back]
    return "validate" if applied else "gate"


def route_after_validate(state: AuditState) -> str:
    v = state["validation"]
    done = v.passed and not v.remaining
    nothing_to_fix = not triage.blocking(state["prioritized"])
    if done or nothing_to_fix or state.get("fix_attempts", 0) >= state.get("max_fix_attempts", 0):
        return "gate"
    return "fix"


def route_after_gate(state: AuditState) -> str:
    return "deploy" if state["verdict"] == "CLEAN" and state.get("deploy_target", "none") != "none" else "report"


# --------------------------------------------------------------------------- graph
def build_graph():
    g = StateGraph(AuditState)
    g.add_node("scan", scan_node)
    g.add_node("triage", triage_node)
    g.add_node("fix", fix_node)
    g.add_node("validate", validate_node)
    g.add_node("gate", gate_node)
    g.add_node("deploy", deploy_node)
    g.add_node("report", report_node)

    g.add_edge(START, "scan")
    g.add_edge("scan", "triage")
    g.add_conditional_edges("triage", route_after_triage, {"fix": "fix", "validate": "validate", "gate": "gate"})
    g.add_conditional_edges("fix", route_after_fix, {"validate": "validate", "gate": "gate"})
    g.add_conditional_edges("validate", route_after_validate, {"fix": "fix", "gate": "gate"})
    g.add_conditional_edges("gate", route_after_gate, {"deploy": "deploy", "report": "report"})
    g.add_edge("deploy", "report")
    g.add_edge("report", END)
    return g.compile()
