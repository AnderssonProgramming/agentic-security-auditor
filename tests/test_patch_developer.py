import json

import pytest

from auditor.agents import patch_developer as pd

SOURCE = """import { db } from "../db";

export async function getUser(req, res) {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows[0]);
}
"""

GOOD_ORIGINAL = "await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);"
GOOD_REPLACEMENT = 'await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);'


@pytest.fixture
def sqli(make_finding):
    return make_finding(kind="code", rule_id="sqli", file="src/routes/users.ts", package=None, line=4)


def test_valid_patch_is_applied(sqli):
    patched = pd.validate_code_patch(
        sqli, SOURCE, {"can_fix": True, "original": GOOD_ORIGINAL, "replacement": GOOD_REPLACEMENT, "rationale": "bind"}
    )
    assert "$1" in patched and "${req.params.id}" not in patched


@pytest.mark.parametrize(
    "answer, reason",
    [
        ({"can_fix": False, "rationale": "no principal in scope"}, "declined"),
        ({"can_fix": True, "original": "not in file", "replacement": "x", "rationale": ""}, "matched 0"),
        ({"can_fix": True, "original": GOOD_ORIGINAL, "replacement": "// @ts-ignore\n" + GOOD_REPLACEMENT, "rationale": ""}, "type-check"),
        ({"can_fix": True, "original": GOOD_ORIGINAL, "replacement": "await db.query(`SELECT * FROM users WHERE id = ${Number(req.params.id)}`);", "rationale": ""}, "interpolated SQL"),
        ({"can_fix": True, "original": GOOD_ORIGINAL, "replacement": "\n".join(["x;"] * 60), "rationale": ""}, "limit"),
    ],
)
def test_guardrails_reject_unsafe_patches(sqli, answer, reason):
    with pytest.raises(pd.PatchRejected, match=reason):
        pd.validate_code_patch(sqli, SOURCE, answer)


def test_protected_paths_cannot_be_patched(make_finding):
    test_file = make_finding(kind="code", file="src/users.test.ts", package=None)
    with pytest.raises(pd.PatchRejected, match="protected"):
        pd.validate_code_patch(test_file, SOURCE, {"can_fix": True, "original": GOOD_ORIGINAL, "replacement": "x"})


def test_dependency_plan_upgrades_direct_overrides_transitive_and_escalates_major(make_finding):
    package_json = {"dependencies": {"lodash": "^4.17.20"}}

    assert pd.plan_dependency_fix(make_finding(package="lodash", fixed_version="4.17.21"), package_json) == (
        "dependency-upgrade",
        "^4.17.21",
    )
    assert pd.plan_dependency_fix(make_finding(package="qs", fixed_version="6.7.3", installed_version="6.7.0"), package_json) == (
        "dependency-override",
        "^6.7.3",
    )
    assert pd.plan_dependency_fix(make_finding(package="lodash", fixed_version="5.0.0"), package_json) is None


def test_code_fix_snapshot_allows_exact_rollback(tmp_path, sqli):
    target = tmp_path / "src" / "routes" / "users.ts"
    target.parent.mkdir(parents=True)
    target.write_text(SOURCE, encoding="utf-8")
    llm = lambda system, user: {"can_fix": True, "original": GOOD_ORIGINAL, "replacement": GOOD_REPLACEMENT, "rationale": "bind"}

    patch = pd.apply_code_fix(str(tmp_path), sqli, llm)
    assert "$1" in target.read_text(encoding="utf-8")
    assert patch.diff.startswith("--- a/src/routes/users.ts")

    pd.restore(str(tmp_path), patch)
    assert target.read_text(encoding="utf-8") == SOURCE
    assert patch.rolled_back


def test_develop_patches_escalates_secrets_and_code_without_llm(tmp_path, make_finding):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
    secret = make_finding(kind="secret", rule_id="aws", file=".env", package=None)
    code = make_finding(kind="code", rule_id="sqli", file="a.ts", package=None)

    patches, escalations = pd.develop_patches(str(tmp_path), [secret, code], llm=None)

    assert patches == []
    assert len(escalations) == 2
