"""Sandboxed shell tool shared by every agent.

Agents never get a free-form shell: only binaries on ``ALLOWED_BINARIES`` can run,
arguments are passed as a list (no shell interpolation) and every call has a timeout.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

ALLOWED_BINARIES = {
    "npm",
    "npx",
    "node",
    "trivy",
    "semgrep",
    "gitleaks",
    "snyk",
    "git",
    "netlify",
    "fastlane",
    "bundle",
}

# Secrets that must never reach scanner or test subprocesses.
_SCRUBBED_ENV = {"ANTHROPIC_API_KEY", "NETLIFY_AUTH_TOKEN", "PLAY_STORE_JSON_KEY_PATH"}


class ToolNotAllowed(RuntimeError):
    pass


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing_binary: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing_binary

    def tail(self, lines: int = 40) -> str:
        return "\n".join((self.stdout + "\n" + self.stderr).strip().splitlines()[-lines:])


def run(
    args: list[str],
    cwd: str,
    timeout: int = 600,
    keep_secrets: tuple[str, ...] = (),
) -> CommandResult:
    """Run an allow-listed CLI tool and capture its output.

    ``keep_secrets`` opts specific secrets back in (e.g. the deploy step needs
    ``NETLIFY_AUTH_TOKEN``); everything else in ``_SCRUBBED_ENV`` is removed.
    """
    binary = args[0]
    if binary not in ALLOWED_BINARIES:
        raise ToolNotAllowed(f"'{binary}' is not an allow-listed tool")

    resolved = shutil.which(binary)
    if resolved is None:
        return CommandResult(args, 127, "", f"{binary}: not found on PATH", missing_binary=True)

    env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV or k in keep_secrets}
    env.setdefault("CI", "true")
    try:
        proc = subprocess.run(
            [resolved, *args[1:]],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(args, 124, exc.stdout or "", exc.stderr or "", timed_out=True)
    return CommandResult(args, proc.returncode, proc.stdout, proc.stderr)
