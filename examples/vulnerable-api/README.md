# vulnerable-api (demo target)

Intentionally vulnerable Express + TypeScript service used to exercise the auditor end to end. **Never deploy it.**

| Planted issue | Where | Expected detector |
|---|---|---|
| SQL injection in an ORM-less query (CWE-89) | `GET /api/products` | Semgrep `node-sqli-raw-query-string-building` |
| IDOR on invoices (CWE-639) | `GET /api/invoices/:id` | Semgrep `express-idor-unscoped-lookup-by-id` + Triage LLM review |
| Vulnerable `lodash@4.17.20` (CVE-2021-23337) | `package.json` | npm audit + Trivy (merged) |
| Vulnerable `express@4.17.1` (transitive `qs`, `body-parser`) | `package.json` | npm audit + Trivy |

`test/app.test.ts` encodes the behavioural contract **and** two security acceptance tests (no user input in SQL text; invoice lookup bound to the caller). They fail on the vulnerable code and must pass after the Patch Developer's fixes, which is what the Validator checks.

```bash
npm install
security-auditor --repo examples/vulnerable-api --target netlify   # dry-run deploy
```
