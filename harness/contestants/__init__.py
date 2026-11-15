"""Contestants: one adapter per agent SDK acting as an MCP client.

Each adapter is given the same task, the same (generic) stdio server specs, the same system prompt and the
same limits, and returns an AgentResult. Claude and GPT costs: the Claude SDK reports its own; the others
go through LiteLLM, so we price from token counts using LiteLLM's bundled price map (same table for all).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

import litellm

from ..config import Limits  # noqa: F401  (re-exported for adapters)


@dataclass
class ServerSpec:
    name: str              # logical name the agent sees (files, comms, helper)
    command: str
    args: list[str]
    env: dict[str, str]


@dataclass
class AgentResult:
    final_text: str = ""
    model_calls: int = 0
    input_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    cost_source: str = ""
    blocked_calls: int = 0        # calls the approval policy refused
    stopped_by: str = "done"      # done | max_calls | budget | wall_clock | error
    error: str | None = None
    extra: dict = field(default_factory=dict)


Runner = Callable[..., Awaitable[AgentResult]]


def price_from_tokens(model: str, r: AgentResult) -> float | None:
    bare = model.split("/")[-1]
    info = next((litellm.model_cost[k] for k in (model, bare, f"openai/{bare}", f"anthropic/{bare}") if k in litellm.model_cost), None)
    if not info:
        return None
    inp = info.get("input_cost_per_token") or 0
    out = info.get("output_cost_per_token") or 0
    cread = info.get("cache_read_input_token_cost") or inp
    return round(r.input_tokens * inp + r.cache_read_tokens * cread + r.output_tokens * out, 5)


def registry() -> dict[str, Runner]:
    from . import adk, claude_sdk, openai_agents
    return {"claude-sdk": claude_sdk.run, "openai-agents": openai_agents.run, "adk": adk.run}
