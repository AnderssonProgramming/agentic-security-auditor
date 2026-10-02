"""Render the post-production quality report (Markdown) and a machine-readable JSON twin."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from auditor import __version__
from auditor.agents.triage import blocking
from auditor.state import AuditState, Finding

TEMPLATES = Path(__file__).resolve().parent / "templates"
VERDICT_ICONS = {"CLEAN": "✅", "REMEDIATED": "🛠️", "BLOCKED": "⛔", "PENDING": "⏳"}
PRIORITY_LABELS = {"P0": "Critical", "P1": "High", "P2": "Medium", "P3": "Low"}
SCANNERS = [
    ("npm-audit", "Dependency CVEs (npm advisory DB)"),
    ("trivy", "Dependency CVEs, secrets, IaC misconfig"),
    ("semgrep", "SAST: injection, IDOR, unsafe sinks"),
    ("gitleaks", "Secrets in working tree"),
    ("snyk", "Dependency CVEs (Snyk DB, optional)"),
]


def _location(f: Finding) -> str:
    if f.kind == "dependency":
        return f"`{f.package}@{f.installed_version}`"
    return f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"


def _row(f: Finding, still_blocking: set[str], patched: set[str]) -> dict:
    if f.false_positive:
        status = "suppressed (FP)"
    elif f.fingerprint in still_blocking:
        status = "❌ open"
    elif f.fingerprint in patched:
        status = "✅ fixed"
    else:
        status = "open (non-blocking)"
    return {**f.to_dict(), "location": _location(f), "status": status}


def build_context(state: AuditState) -> dict:
    baseline = state.get("prioritized", [])
    validation = state.get("validation")
    patches = state.get("patches", [])
    patched = {p.finding_fingerprint for p in patches if p.applied and not p.rolled_back}
    if validation:
        still_blocking = set(validation.remaining)
        after = [f for f in baseline if f.fingerprint not in patched]
    else:
        still_blocking = {f.fingerprint for f in blocking(baseline)}
        after = baseline
    tool_errors = state.get("tool_errors", [])
    errored = {e.split(":", 1)[0] for e in tool_errors}
    snyk = bool(os.environ.get("SNYK_TOKEN"))

    return {
        "icon": VERDICT_ICONS.get(state.get("verdict", "PENDING"), ""),
        "verdict": state.get("verdict", "PENDING"),
        "verdict_reasons": state.get("verdict_reasons", []),
        "repo": state.get("repo_path"),
        "commit_sha": state.get("commit_sha"),
        "run_id": state.get("run_id"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "deploy_target": state.get("deploy_target", "none"),
        "deployment": state.get("deployment") or {},
        "fix_attempts": state.get("fix_attempts", 0),
        "max_fix_attempts": state.get("max_fix_attempts", 0),
        "priority_labels": PRIORITY_LABELS,
        "counts_before": Counter(f.priority for f in baseline if not f.false_positive),
        "counts_after": Counter(f.priority for f in after if not f.false_positive),
        "blocking_before": len(blocking(baseline)),
        "blocking_after": len(still_blocking),
        "scanners": [
            {
                "name": name,
                "scope": scope,
                "status": "⚠️ error" if name in errored else ("skipped" if name == "snyk" and not snyk else "✅ ran"),
            }
            for name, scope in SCANNERS
        ],
        "tool_errors": tool_errors,
        "findings": [_row(f, still_blocking, patched) for f in baseline if not f.false_positive],
        "false_positives": [_row(f, still_blocking, patched) for f in baseline if f.false_positive],
        "patches": patches,
        "escalations": state.get("escalations", []),
        "validation": validation,
        "snyk": snyk,
        "version": __version__,
    }


def render(state: AuditState) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), keep_trailing_newline=True, autoescape=False)
    return env.get_template("quality_report.md.j2").render(**build_context(state))


def write(state: AuditState, out_dir: str) -> str:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path = out / f"security-report-{state.get('run_id', 'local')}.md"
    md_path.write_text(render(state), encoding="utf-8")

    summary = {
        "verdict": state.get("verdict"),
        "reasons": state.get("verdict_reasons", []),
        "findings": [f.to_dict() for f in state.get("prioritized", [])],
        "patches": [{k: v for k, v in asdict(p).items() if k != "snapshot"} for p in state.get("patches", [])],
        "validation": asdict(state["validation"]) if state.get("validation") else None,
        "deployment": state.get("deployment"),
    }
    md_path.with_suffix(".json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return str(md_path)
