"""Quality gate and Deployment agent.

Verdicts:
  CLEAN       - the commit as pushed has no blocking findings, every required scanner
                ran, and tests pass. Only this verdict can deploy.
  REMEDIATED  - blocking findings existed but the Fixer produced patches that passed
                validation. The patches go out as an autofix PR; the commit itself is
                NOT deployed (unreviewed machine-written code never ships directly).
                Merging the PR triggers a fresh audit that can produce CLEAN.
  BLOCKED     - anything else: unfixed blocking findings, regressions, failing tests,
                or an incomplete scan (fail closed).
"""

from __future__ import annotations

import os
from pathlib import Path

from auditor.agents.triage import blocking
from auditor.state import AuditState
from auditor.tools.shell import run


def evaluate_gate(state: AuditState) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if state.get("tool_errors"):
        reasons += [f"incomplete scan: {e}" for e in state["tool_errors"]]

    baseline_blocking = blocking(state.get("prioritized", []))
    validation = state.get("validation")

    if not baseline_blocking:
        if validation is not None and not validation.tests_ok:
            reasons.append("test suite failed")
        return ("BLOCKED" if reasons else "CLEAN"), reasons or ["0 blocking findings, all scanners completed"]

    if validation is None:
        reasons.append(f"{len(baseline_blocking)} blocking finding(s) and no validated fix")
        return "BLOCKED", reasons
    if not validation.passed:
        if not validation.install_ok:
            reasons.append("dependency install failed after patching")
        if not validation.typecheck_ok:
            reasons.append("type check failed after patching")
        if not validation.tests_ok:
            reasons.append("test suite failed after patching")
        if validation.regressions:
            reasons.append(f"{len(validation.regressions)} new finding(s) introduced by patches")
    if validation.remaining:
        reasons.append(f"{len(validation.remaining)} blocking finding(s) remain after patching")
    if reasons:
        return "BLOCKED", reasons
    return "REMEDIATED", [
        f"{len(baseline_blocking)} blocking finding(s) fixed and validated; awaiting autofix PR merge"
    ]


def deploy(state: AuditState) -> dict:
    """Run the deploy command for the configured target. Only ever called on CLEAN."""
    if state.get("verdict") != "CLEAN":
        raise RuntimeError("refusing to deploy: verdict is not CLEAN")

    target = state.get("deploy_target", "none")
    repo = state["repo_path"]
    if target == "netlify":
        args = [
            "netlify", "deploy", "--prod",
            "--dir", os.environ.get("NETLIFY_PUBLISH_DIR", "dist"),
            "--site", os.environ.get("NETLIFY_SITE_ID", ""),
            "--message", f"audit {state.get('run_id')} @ {state.get('commit_sha', '')[:7]}",
            "--json",
        ]
        secrets = ("NETLIFY_AUTH_TOKEN",)
    elif target == "play-store":
        # fastlane supply uploads the signed AAB to the internal track; promotion to
        # production stays a manual, staged-rollout decision in the Play Console.
        args = [
            "fastlane", "supply",
            "--aab", os.environ.get("ANDROID_AAB_PATH", "android/app/build/outputs/bundle/release/app-release.aab"),
            "--track", os.environ.get("PLAY_TRACK", "internal"),
            "--package_name", os.environ.get("ANDROID_PACKAGE_NAME", ""),
            "--json_key", os.environ.get("PLAY_STORE_JSON_KEY_PATH", ""),
        ]
        secrets = ("PLAY_STORE_JSON_KEY_PATH",)
    else:
        return {"target": "none", "status": "skipped"}

    if state.get("dry_run", True):
        return {"target": target, "status": "dry-run", "command": " ".join(args)}

    result = run(args, cwd=repo, timeout=1800, keep_secrets=secrets)
    return {
        "target": target,
        "status": "deployed" if result.ok else "failed",
        "output": result.tail(20),
    }


def write_github_outputs(state: AuditState) -> None:
    """Expose the verdict to later workflow jobs (the deploy job's `if:` condition)."""
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with Path(out).open("a", encoding="utf-8") as fh:
        fh.write(f"verdict={state.get('verdict', 'BLOCKED')}\n")
        fh.write(f"report_path={state.get('report_path', '')}\n")
        fh.write(f"patches={len([p for p in state.get('patches', []) if p.applied and not p.rolled_back])}\n")
