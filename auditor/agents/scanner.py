"""Scanner agent: runs every security-scan skill and merges the results.

A scanner that is missing or crashes is recorded in ``tool_errors``. The gate treats
an incomplete scan as *not clean*, so a broken tool can never produce a green build.
"""

from __future__ import annotations

import os
import tempfile

from auditor.state import Finding
from auditor.tools import scanners

REQUIRED_SCANNERS = ("npm-audit", "trivy", "semgrep")


def scan(repo: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    def collect(name: str, outcome):
        found, result = outcome
        findings.extend(found)
        if result.missing_binary:
            if name in REQUIRED_SCANNERS:
                errors.append(f"{name}: not installed")
        # Scanners exit 1 when they find something, which is not a tool failure.
        elif result.timed_out or (result.returncode not in (0, 1) and not found):
            errors.append(f"{name}: {result.tail(5) or 'exit ' + str(result.returncode)}")

    collect("npm-audit", scanners.npm_audit(repo))
    collect("trivy", scanners.trivy_fs(repo))
    collect("semgrep", scanners.semgrep_scan(repo))

    with tempfile.TemporaryDirectory() as tmp:
        collect("gitleaks", scanners.gitleaks_scan(repo, os.path.join(tmp, "gitleaks.json")))

    if os.environ.get("SNYK_TOKEN"):
        collect("snyk", scanners.snyk_test(repo))

    return findings, errors
