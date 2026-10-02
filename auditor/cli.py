"""Command-line entry point: ``security-auditor --repo ./app --target netlify``.

Exit codes (consumed by CI): 0 = CLEAN, 1 = BLOCKED, 2 = REMEDIATED (fixes ready in
the working tree, commit as-is is not deployable).
"""

from __future__ import annotations

import argparse
import os
import sys

EXIT_CODES = {"CLEAN": 0, "BLOCKED": 1, "REMEDIATED": 2}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-auditor", description=__doc__)
    parser.add_argument("--repo", default=".", help="path to the Node.js/TypeScript project")
    parser.add_argument("--target", choices=["netlify", "play-store", "none"], default="none")
    parser.add_argument("--deploy", action="store_true", help="actually deploy on CLEAN (default: dry run)")
    parser.add_argument("--max-fix-attempts", type=int, default=2, help="0 disables the Fixer")
    parser.add_argument("--report-dir", default="reports")
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    args = parser.parse_args(argv)

    from auditor.graph import build_graph

    final = build_graph().invoke(
        {
            "repo_path": os.path.abspath(args.repo),
            "run_id": args.run_id,
            "deploy_target": args.target,
            "dry_run": not args.deploy,
            "max_fix_attempts": args.max_fix_attempts,
            "report_dir": args.report_dir,
            "patches": [],
            "escalations": [],
            "fix_attempts": 0,
            "validation": None,
            "tool_errors": [],
        }
    )
    print(f"verdict: {final['verdict']}")
    for reason in final.get("verdict_reasons", []):
        print(f"  - {reason}")
    print(f"report: {final.get('report_path')}")
    return EXIT_CODES.get(final["verdict"], 1)


if __name__ == "__main__":
    sys.exit(main())
