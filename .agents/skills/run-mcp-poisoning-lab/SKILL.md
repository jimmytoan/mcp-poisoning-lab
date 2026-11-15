---
name: run-mcp-poisoning-lab
description: >
  Re-run the MCP poisoning lab in this repo — the local, harmless defensive-security measurement of how
  often MCP prompt-injection attacks succeed against the Claude Agent SDK, OpenAI Agents SDK and Google ADK
  as MCP clients, and which defences stop them. Use when asked to re-run the lab, reproduce the numbers, add
  a model or attack, run the attack or defence rounds, or regenerate the report. Everything stays local.
---

# Run the MCP poisoning lab

This repo is a reproducible lab: a deliberately malicious MCP server, pointed at three agent SDKs, scored
objectively from audit logs (no LLM judge). See `README.md` for the question, the attack set and the safety
boundaries. This skill is the operational runbook for re-running it.

## Safety (always true — do not change)
- Everything is local. No server reaches the network; the "exfil" is an append to a local JSONL file and
  `send_message` sends nothing. The only "secret" is a per-run random canary in a temp sandbox.
- Never commit `.env` (it is git-ignored). Never print API-key values — print only key names with set/empty.
- This lab makes paid model calls. Estimate cost before large runs and keep concurrency at 1 if other work
  shares the same API keys.

## 1. Setup (once)
```bash
cd <repo root>
uv sync --group dev                 # installs SDKs, mcp, and litellm[proxy]
cp .env.example .env                # then add ANTHROPIC_API_KEY / OPENAI_API_KEY (GEMINI optional)
```
Verify keys are present without printing values:
```bash
while IFS= read -r l; do case "$l" in ''|\#*) continue;; esac; k="${l%%=*}"; v="${l#*=}"; [ -n "$v" ] && echo "$k set" || echo "$k empty"; done < .env
```

## 2. Unit tests (no model calls, no cost — run these first)
```bash
uv run python -m tests.test_servers     # or: uv run pytest -q
```
All server behaviour and the scorer are tested here. If these fail, fix before spending on model runs.

## 3. Start the proxy ONLY if running GPT models on the Claude Agent SDK
The Claude Agent SDK speaks the Anthropic API natively. To let it drive GPT models it is pointed at a local
LiteLLM proxy exposing an Anthropic-compatible endpoint. Skip this if you are not running `claude-sdk` with a
`gpt-*` model.
```bash
uv run litellm --config harness/proxy_config.yaml --port 8111 &
curl -s -H "x-api-key: sk-lab-local" http://localhost:8111/health/liveliness   # -> "I'm alive!"
```
Kill it when done: `pkill -f "litellm --config harness/proxy_config.yaml"` (or by PID).

## 4. Smoke test (a few cents)
```bash
uv run python -m harness.run --scenarios 01 --contestants claude-sdk,openai-agents,adk --model claude-haiku-5-5 --tag smoke
```
Confirms the plumbing for all three clients end-to-end before a large batch.

## 5. Attack rounds
Scenarios: `01-05` are blatant attacks, `06-09` are subtle (legitimacy-framed) attacks. Contestants:
`claude-sdk` (Claude native; GPT via the proxy), `openai-agents`, `adk`. `--repeat` sets trials per cell.
```bash
# subtle attacks across cells, no defences, n=5
uv run python -m harness.run --scenarios 06,07,08,09 --repeat 5 --defences none --tag attack \
    --model claude-haiku-5-5 --contestants claude-sdk,openai-agents,adk
# repeat per model: claude-opus-5-5, claude-sonnet-5-5, gpt-6.1-sol, gpt-6.1-terra, gpt-6-luna
```
Run one model at a time (concurrency 1) when sharing keys with other work.

## 6. Defence round (only where the attack round showed hits)
Defences combine with `+`; list several comma-separated sets. Available: `allowlist`, `sys_warn`,
`approval`, `pinning` (pinning targets the rug pull).
```bash
uv run python -m harness.run --scenarios 06,07 --repeat 5 --tag defence \
    --defences none,allowlist,sys_warn,approval,pinning \
    --model gpt-6-luna --contestants openai-agents
```
Defences against a cell/attack with a 0 baseline measure nothing — scope this to cells that actually fell.

## 7. Report
```bash
uv run python -m harness.report --tag attack     # or --tag defence, or omit for all
```
Tables: attack success by model×SDK, by attack×SDK, by defence, and runs that errored.

## Known quirks (do not re-investigate)
- `claude-sdk` + `gpt-*`: the SDK's reported `cost_usd` is Anthropic-priced, so it is approximate for those
  cells; real spend is on the OpenAI key. A `[claude-code:unrecognized_model]` warning is harmless.
- `claude-sdk` with a Claude model needs the adapter to pass `env={}` (not `None`) to `ClaudeAgentOptions`,
  or it raises `'NoneType' object is not a mapping`. This is already handled.
- Scenario `05-overbroad-parameter` trips Anthropic's content filter on opus/sonnet (runs error out). That
  is a provider-layer block, not a harness bug.
- The LiteLLM proxy refuses to start without a master key; `harness/proxy_config.yaml` sets a local-only one
  (`sk-lab-local`). It is not a secret and the proxy binds to localhost.

## Adding to the matrix
- New model: pass `--model <id>` (must work on the configured key). GPT ids need the proxy for `claude-sdk`.
- New attack: add a mode in `harness/servers/malicious_server.py` and a `scenarios/NN-*/scenario.yaml`; add
  a unit test in `tests/test_servers.py`. Keep it local and harmless.
