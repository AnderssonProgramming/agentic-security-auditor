# agentic-security-auditor

A multi-agent security auditor for Node.js/TypeScript repositories, built on **LangGraph** and **Claude**. On every pull request it scans dependencies and first-party code, prioritizes findings by CVSS and context, tries guarded fixes, validates them against the test suite, and lets a deployment to **Netlify** or the **Google Play Store** go out only when the commit is `CLEAN`.

```
scan → triage → (fix → validate)* → gate → [deploy] → report
```

| Agent | What it does |
|---|---|
| Scanner | npm audit, Trivy, Semgrep (with custom IDOR / raw-SQLi rules), Gitleaks, optional Snyk |
| Triage Officer | De-duplicates across tools, scores risk from CVSS and context, assigns P0–P3, uses an LLM to review IDOR/SQLi hits |
| Patch Developer | Same-major dependency upgrades or overrides; LLM code refactors behind guardrails |
| Validator | `npm ci`, `tsc --noEmit`, `npm test`, re-scan, regression diff, rollback |
| Quality Gate | `CLEAN` / `REMEDIATED` / `BLOCKED`; fails closed |
| Deployment Agent | `netlify deploy --prod` or `fastlane supply`, only on `CLEAN` |
| Reporter | Markdown + JSON post-production quality report |

**Docs:** [Architecture](docs/ARCHITECTURE.md) · [Challenge submission](docs/SUBMISSION.md) · [Sample report](docs/sample-report.md)

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env                                   # set ANTHROPIC_API_KEY to enable LLM triage and fixes

# Required on PATH: node/npm, trivy, semgrep, gitleaks (snyk optional)
cd examples/vulnerable-api && npm install && cd -
security-auditor --repo examples/vulnerable-api --target netlify            # deploy is a dry run
security-auditor --repo ./my-app --target netlify --deploy                  # real deploy on CLEAN
```

Exit codes: `0` CLEAN · `1` BLOCKED · `2` REMEDIATED. Reports are written to `reports/`.

Without `ANTHROPIC_API_KEY`, the pipeline still runs end to end: code findings are escalated to a human instead of being patched, and triage falls back to deterministic scoring.

## CI/CD

- `.github/workflows/security-audit.yml` runs the audit on PRs (fixer on, report as a PR comment, autofix PR when the verdict is `REMEDIATED`) and on `main` (fixer off). It deploys to Netlify or the Play Store only when `verdict == CLEAN`.
- `.github/workflows/ci.yml` runs the unit tests and checks the custom Semgrep rules against annotated fixtures.

Configure with repository variables `APP_DIR` and `DEPLOY_TARGET` (`netlify` | `play-store`), and these secrets: `ANTHROPIC_API_KEY`, `NETLIFY_AUTH_TOKEN`, `NETLIFY_SITE_ID`, `PLAY_STORE_JSON_KEY`, `ANDROID_KEYSTORE_*`, and optionally `SNYK_TOKEN`.

## Layout

```
auditor/
  graph.py              LangGraph state machine and routing
  state.py              Finding / Patch / ValidationResult / AuditState
  prompts.py            Triage Officer and Patch Developer system prompts and tool schemas
  agents/               scanner, triage, patch_developer, validator
  tools/                sandboxed shell and scanner skills (run + parse)
  rules/                custom Semgrep rules (IDOR, raw SQL injection)
  deploy.py             quality gate and Netlify / Play Store deployment
  report.py, templates/ post-production quality report
examples/vulnerable-api intentionally vulnerable Express/TS target
tests/                  pytest suite and Semgrep rule fixtures
```

## Development

```bash
pytest -q
semgrep --test --config auditor/rules tests/semgrep   # Linux/macOS/WSL
```
