"""OpenAI Agents SDK as an MCP client. GPT models use the native provider; Claude goes through LiteLLM."""

from __future__ import annotations

from agents import Agent, ModelSettings, Runner, set_tracing_disabled
from agents.exceptions import MaxTurnsExceeded
from agents.extensions.models.litellm_model import LitellmModel
from agents.mcp import MCPServerStdio
from agents.tool_guardrails import ToolGuardrailFunctionOutput, ToolInputGuardrail
from openai.types.shared import Reasoning

from ..config import Limits, user_prompt
from ..policy import risky_call
from . import AgentResult, ServerSpec, price_from_tokens

set_tracing_disabled(True)


def _guardrail(counter: dict) -> ToolInputGuardrail:
    def check(data):  # noqa: ANN001
        ctx = getattr(data, "context", data)
        name = getattr(ctx, "tool_name", "") or ""
        raw = getattr(ctx, "tool_arguments", None)
        args = raw if isinstance(raw, dict) else {}
        if not args:
            import json
            try:
                args = json.loads(raw) if isinstance(raw, str) else {}
            except Exception:
                args = {}
        reason = risky_call(name, args)
        if reason:
            counter["n"] += 1
            return ToolGuardrailFunctionOutput.reject_content(message=reason)
        return ToolGuardrailFunctionOutput.allow()

    return ToolInputGuardrail(guardrail_function=check, name="lab-policy")


async def run(task: str, system_prompt: str, servers: list[ServerSpec], model: str,
              limits: Limits, approval: bool = False) -> AgentResult:
    blocked = {"n": 0}
    guard = [_guardrail(blocked)] if approval else None

    mcp_servers = [
        MCPServerStdio(
            params={"command": s.command, "args": s.args, "env": s.env},
            cache_tools_list=True,
            name=s.name,
            client_session_timeout_seconds=30,
            tool_input_guardrails=guard,
        )
        for s in servers
    ]

    if model.startswith("claude"):
        llm = LitellmModel(model=f"anthropic/{model}")
        settings = ModelSettings(include_usage=True)
    else:
        llm = model
        settings = ModelSettings(reasoning=Reasoning(effort="medium"))

    result = AgentResult(cost_source="litellm-price-map")
    run_result = None
    opened = []
    try:
        for srv in mcp_servers:
            await srv.connect()
            opened.append(srv)
        agent = Agent(name="assistant", instructions=system_prompt, mcp_servers=mcp_servers,
                      model=llm, model_settings=settings)
        try:
            run_result = await Runner.run(agent, user_prompt(task), max_turns=limits.max_model_calls)
        except MaxTurnsExceeded as exc:
            result.stopped_by = "max_calls"
            run_result = getattr(exc, "run_data", None)
    finally:
        for srv in reversed(opened):
            try:
                await srv.cleanup()
            except Exception:
                pass

    if run_result is not None:
        usage = run_result.context_wrapper.usage
        cached = getattr(getattr(usage, "input_tokens_details", None), "cached_tokens", 0) or 0
        result.model_calls = usage.requests
        result.input_tokens = usage.input_tokens - cached
        result.cache_read_tokens = cached
        result.output_tokens = usage.output_tokens
        result.final_text = str(getattr(run_result, "final_output", "") or "")
    result.blocked_calls = blocked["n"]
    result.cost_usd = price_from_tokens(model, result)
    return result
