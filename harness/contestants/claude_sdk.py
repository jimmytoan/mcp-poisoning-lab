"""Claude Agent SDK as an MCP client."""

from __future__ import annotations

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    TextBlock,
    query,
)

from ..config import PROXY_KEY, PROXY_URL, RUNTIME, SERVER_TOOLS, Limits, user_prompt
from ..policy import risky_call
from . import AgentResult, ServerSpec


async def run(task: str, system_prompt: str, servers: list[ServerSpec], model: str,
              limits: Limits, approval: bool = False) -> AgentResult:
    mcp_servers = {s.name: {"type": "stdio", "command": s.command, "args": s.args, "env": s.env} for s in servers}
    allowed = [f"mcp__{s.name}__{t}" for s in servers for t in SERVER_TOOLS.get(s.name, [])]

    blocked = {"n": 0}

    async def can_use_tool(tool_name, tool_input, context):  # noqa: ANN001, ARG001
        reason = risky_call(tool_name, tool_input or {})
        if reason:
            blocked["n"] += 1
            return PermissionResultDeny(message=reason)
        return PermissionResultAllow()

    scratch = RUNTIME / "claude-cwd"
    scratch.mkdir(parents=True, exist_ok=True)

    # Claude models run natively; non-Claude models are routed through the local Anthropic-compatible proxy.
    is_claude = model.startswith("claude")
    env = {} if is_claude else {"ANTHROPIC_BASE_URL": PROXY_URL, "ANTHROPIC_API_KEY": PROXY_KEY}

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=system_prompt,
        tools=[],                       # no built-in Bash/Read/Edit: only the MCP servers under test
        mcp_servers=mcp_servers,
        allowed_tools=allowed,
        permission_mode="dontAsk",
        setting_sources=[],
        max_turns=limits.max_model_calls,
        max_budget_usd=limits.max_usd,
        effort="medium",
        cwd=str(scratch),
        env=env,
        can_use_tool=can_use_tool if approval else None,
    )

    result = AgentResult(cost_source="sdk" if is_claude else "proxy")
    texts: list[str] = []
    async for msg in query(prompt=user_prompt(task), options=options):
        if isinstance(msg, AssistantMessage):
            texts.extend(b.text for b in msg.content if isinstance(b, TextBlock))
        elif isinstance(msg, ResultMessage):
            usage = msg.usage or {}
            result.model_calls = msg.num_turns
            result.input_tokens = usage.get("input_tokens", 0)
            result.cache_read_tokens = usage.get("cache_read_input_tokens", 0)
            result.cache_write_tokens = usage.get("cache_creation_input_tokens", 0)
            result.output_tokens = usage.get("output_tokens", 0)
            result.cost_usd = msg.total_cost_usd
            result.final_text = msg.result or (texts[-1] if texts else "")
            result.extra = {"subtype": msg.subtype}
            if msg.subtype == "error_max_turns":
                result.stopped_by = "max_calls"
            elif msg.subtype == "error_max_budget_usd":
                result.stopped_by = "budget"
            elif msg.is_error:
                result.stopped_by, result.error = "error", str(msg.errors or msg.subtype)
    result.blocked_calls = blocked["n"]
    if not result.final_text and texts:
        result.final_text = texts[-1]
    return result
