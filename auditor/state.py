"""Shared data model for the audit graph.

Every agent reads from and writes to ``AuditState``. Findings from all scanners are
normalised into ``Finding`` so triage, patching and reporting stay tool-agnostic.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Literal, TypedDict


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def parse(cls, raw: str | None) -> "Severity":
        value = (raw or "").strip().upper()
        aliases = {"MODERATE": "MEDIUM", "ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}
        value = aliases.get(value, value)
        return cls(value) if value in cls.__members__ else cls.INFO


FindingKind = Literal["dependency", "code", "secret", "config"]
Verdict = Literal["CLEAN", "REMEDIATED", "BLOCKED", "PENDING"]


@dataclass
class Finding:
    source: str  # npm-audit | trivy | snyk | semgrep | gitleaks
    kind: FindingKind
    rule_id: str  # CVE / GHSA / semgrep check id
    title: str
    severity: Severity
    cvss: float | None = None
    cwe: list[str] = field(default_factory=list)
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    direct_dependency: bool | None = None
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    url: str | None = None
    aliases: list[str] = field(default_factory=list)  # e.g. GHSA ids for a CVE
    # Filled by the Triage Officer.
    priority: str | None = None  # P0..P3
    risk_score: float | None = None
    false_positive: bool = False
    triage_note: str | None = None

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication and regression detection.

        Line numbers are deliberately excluded so that a patch which shifts code does
        not make an unchanged vulnerability look like a "new" one.
        """
        if self.kind == "dependency":
            key = f"dep|{self.package}|{self.rule_id}"
        else:
            key = f"{self.kind}|{self.rule_id}|{self.file}|{(self.snippet or '').strip()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class Patch:
    finding_fingerprint: str
    strategy: Literal["dependency-upgrade", "dependency-override", "code-refactor"]
    file: str
    description: str
    diff: str = ""
    applied: bool = False
    rolled_back: bool = False
    rationale: str = ""
    # Pre-patch file contents (None = file did not exist), used for rollback.
    snapshot: dict[str, str | None] = field(default_factory=dict, repr=False)


@dataclass
class ValidationResult:
    install_ok: bool
    tests_ok: bool
    typecheck_ok: bool
    remaining: list[str]  # fingerprints still present after re-scan
    regressions: list[str]  # fingerprints that did not exist before patching
    test_output_tail: str = ""

    @property
    def passed(self) -> bool:
        return self.install_ok and self.tests_ok and self.typecheck_ok and not self.regressions


class AuditState(TypedDict, total=False):
    repo_path: str
    run_id: str
    commit_sha: str
    deploy_target: Literal["netlify", "play-store", "none"]
    dry_run: bool
    max_fix_attempts: int
    report_dir: str

    baseline_findings: list[Finding]  # first scan, never mutated
    findings: list[Finding]  # latest scan (post-validation re-scan when patches exist)
    prioritized: list[Finding]  # actionable baseline findings, highest risk first
    patches: list[Patch]
    escalations: list[str]  # findings the Fixer could not (or must not) patch
    fix_feedback: str | None  # validation failure fed back into the next fix attempt
    fix_attempts: int
    validation: ValidationResult | None
    verdict: Verdict
    verdict_reasons: list[str]
    deployment: dict
    report_path: str
    tool_errors: list[str]
