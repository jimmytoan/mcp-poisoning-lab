"""Google ADK as an MCP client. Claude/GPT go through LiteLlm; Gemini uses ADK's native provider."""

from __future__ import annotations

from google.adk.agents import LlmAgent, RunConfig
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.genai import types
from mcp import StdioServerParameters

from ..config import Limits, user_prompt
from ..policy import risky_call
from . import AgentResult, ServerSpec, price_from_tokens


async def run(task: str, system_prompt: str, servers: list[ServerSpec], model: str,
              limits: Limits, approval: bool = False) -> AgentResult:
    blocked = {"n": 0}

    def before_tool(tool, args, tool_context):  # noqa: ANN001, ARG001
        reason = risky_call(getattr(tool, "name", ""), args or {})
        if reason:
            blocked["n"] += 1
            return {"error": reason}
        return None

    toolsets = [
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(command=s.command, args=s.args, env=s.env),
                timeout=30,
            )
        )
        for s in servers
    ]

    if model.startswith("claude"):
        llm = LiteLlm(model=f"anthropic/{model}")
    elif model.startswith("gpt"):
        llm = LiteLlm(model=f"openai/{model}", reasoning_effort="medium")
    else:
        llm = model

    agent = LlmAgent(name="assistant", model=llm, instruction=system_prompt, tools=toolsets,
                     before_tool_callback=before_tool if approval else None)

    sessions = InMemorySessionService()
    session = await sessions.create_session(app_name="lab", user_id="user")
    runner = Runner(agent=agent, app_name="lab", session_service=sessions)

    result = AgentResult(cost_source="litellm-price-map")
    try:
        async for ev in runner.run_async(
            user_id="user",
            session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part(text=user_prompt(task))]),
            run_config=RunConfig(max_llm_calls=limits.max_model_calls),
        ):
            um = ev.usage_metadata
            if um and not ev.partial:
                cached = um.cached_content_token_count or 0
                result.model_calls += 1
                result.input_tokens += (um.prompt_token_count or 0) - cached
                result.cache_read_tokens += cached
                result.output_tokens += (um.candidates_token_count or 0) + (um.thoughts_token_count or 0)
            if ev.is_final_response() and ev.content and ev.content.parts:
                result.final_text = "".join(p.text or "" for p in ev.content.parts)
    except Exception as exc:
        if "LlmCallsLimitExceeded" in type(exc).__name__ or "max_llm_calls" in str(exc):
            result.stopped_by = "max_calls"
        else:
            result.stopped_by, result.error = "error", f"{type(exc).__name__}: {exc}"
    finally:
        for ts in toolsets:
            try:
                await ts.close()
            except Exception:
                pass

    result.blocked_calls = blocked["n"]
    result.cost_usd = price_from_tokens(model, result)
    return result
