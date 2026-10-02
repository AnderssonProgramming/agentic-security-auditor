import pytest

from auditor.state import Finding, Severity


@pytest.fixture
def npm_audit_report():
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "source": 1096305,
                        "name": "lodash",
                        "title": "Command Injection in lodash",
                        "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                        "severity": "high",
                        "cwe": ["CWE-77", "CWE-94"],
                        "cvss": {"score": 7.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
                        "range": "<4.17.21",
                    }
                ],
                "range": "<=4.17.20",
                "fixAvailable": {"name": "lodash", "version": "4.17.21", "isSemVerMajor": False},
            },
            "express": {
                "name": "express",
                "severity": "moderate",
                "isDirect": True,
                "via": ["body-parser"],
                "range": "4.0.0 - 4.19.1",
                "fixAvailable": True,
            },
        },
    }


@pytest.fixture
def trivy_report():
    return {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "VendorIDs": ["GHSA-35jh-r3h4-6jhm"],
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.20",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "nodejs-lodash: command injection via template",
                        "CweIDs": ["CWE-94"],
                        "CVSS": {"nvd": {"V3Score": 7.2}, "ghsa": {"V3Score": 7.2}},
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",
                    },
                    {
                        "VulnerabilityID": "CVE-2022-24999",
                        "PkgName": "qs",
                        "InstalledVersion": "6.7.0",
                        "FixedVersion": "6.7.3, 6.10.3",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 7.5}},
                    },
                ],
            },
            {
                "Target": "src/config.ts",
                "Secrets": [
                    {"RuleID": "aws-access-key-id", "Title": "AWS Access Key", "Severity": "CRITICAL", "StartLine": 3, "Match": "AKIA****"}
                ],
            },
        ]
    }


@pytest.fixture
def semgrep_report():
    return {
        "results": [
            {
                "check_id": "auditor.rules.node-sqli-raw-query-string-building",
                "path": "src/routes/users.ts",
                "start": {"line": 14},
                "extra": {
                    "message": "SQL query built from string concatenation",
                    "severity": "ERROR",
                    "lines": "  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"], "impact": "CRITICAL", "cvss": 9.8},
                },
            }
        ]
    }


@pytest.fixture
def make_finding():
    def _make(**overrides):
        base = dict(
            source="npm-audit",
            kind="dependency",
            rule_id="GHSA-xxxx",
            title="Prototype pollution",
            severity=Severity.HIGH,
            cvss=7.5,
            package="pkg",
            installed_version="1.2.0",
            fixed_version="1.2.5",
        )
        base.update(overrides)
        return Finding(**base)

    return _make
