"""Thin wrapper that forces the model to answer through a single tool schema."""

from __future__ import annotations

import os
from typing import Callable

DEFAULT_MODEL = "claude-sonnet-5-5"

LLMFn = Callable[[str, str], dict]


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def tool_caller(tool: dict, model: str | None = None, max_tokens: int = 4096) -> LLMFn:
    """Return ``fn(system, user) -> dict`` that yields the forced tool call's input."""
    import anthropic

    client = anthropic.Anthropic()
    model = model or os.environ.get("AUDITOR_MODEL", DEFAULT_MODEL)

    def call(system: str, user: str) -> dict:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=0,
            system=system,
            tools=[tool],
            tool_choice={"type": "tool", "name": tool["name"]},
            messages=[{"role": "user", "content": user}],
        )
        for block in response.content:
            if block.type == "tool_use" and block.name == tool["name"]:
                return dict(block.input)
        return {}

    return call
