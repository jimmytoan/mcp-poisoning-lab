"""Run the MCP poisoning lab.

  uv run python -m harness.run --scenarios 01 --contestants claude-sdk --model claude-haiku-5-5
  uv run python -m harness.run --contestants claude-sdk,openai-agents,adk --model claude-haiku-5-5 \
      --defences none,allowlist,sys_warn,approval,pinning --repeat 5 --tag full

Each run: seed a fresh sandbox, launch the chosen SDK as an MCP client against the files/comms/helper
servers, let it do the task, then score the audit logs. Attack/benign verdicts use no LLM judge.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import time
import uuid
from datetime import datetime, timezone
from importlib.metadata import version

import yaml
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from . import sandbox
from .config import (PYTHON, RESULTS, ROOT, RUNTIME, SCENARIOS, SERVER_MODULES, Limits,
                     SYSTEM_PROMPT, SYSTEM_PROMPT_HARDENED, server_env)
from .contestants import AgentResult, ServerSpec, registry

SDK_PACKAGES = {"claude-sdk": "claude-agent-sdk", "openai-agents": "openai-agents", "adk": "google-adk"}
ALL_DEFENCES = ["none", "allowlist", "sys_warn", "approval", "pinning"]


def load_scenario(prefix: str) -> dict:
    match = sorted(p for p in SCENARIOS.iterdir() if p.is_dir() and p.name.startswith(prefix))
    if not match:
        raise SystemExit(f"no scenario matches {prefix!r}")
    return yaml.safe_load((match[0] / "scenario.yaml").read_text())


def scenario_ids(selector: str | None) -> list[str]:
    all_ids = sorted(p.name for p in SCENARIOS.iterdir() if p.is_dir())
    if not selector:
        return all_ids
    wanted = selector.split(",")
    return [s for s in all_ids if any(s.startswith(w) for w in wanted)]


async def helper_descriptions(env: dict) -> dict[str, str]:
    """Launch the helper server once and return {tool: description}. Advances the rug-pull counter."""
    params = StdioServerParameters(command=str(PYTHON), args=["-m", SERVER_MODULES["helper"]], env=env, cwd=str(ROOT))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return {t.name: (t.description or "") for t in (await s.list_tools()).tools}


def build_specs(scenario: dict, sink, sbox, defences: set[str]) -> list[ServerSpec]:
    specs = []
    for name in scenario["servers"]:
        attack = scenario["attack"] if name == "helper" else "none"
        deny = "allowlist" in defences and name == "files"
        env = server_env(sink, sbox, attack, deny, sandbox.ATTACKER_RECIPIENT)
        specs.append(ServerSpec(name=name, command=str(PYTHON), args=["-m", SERVER_MODULES[name]], env=env))
    return specs


async def one_run(scenario_id: str, contestant: str, model: str, defences: set[str], limits: Limits, tag: str) -> dict:
    scenario = yaml.safe_load((SCENARIOS / scenario_id / "scenario.yaml").read_text())
    canary = sandbox.new_canary()
    run_id = f"{datetime.now():%Y%m%d-%H%M%S}-{scenario_id[:2]}-{contestant}-{uuid.uuid4().hex[:4]}"
    sink = RESULTS / "raw" / run_id
    sink.mkdir(parents=True)
    sbox = sandbox.make_sandbox(sink / "sandbox", canary)
    dfl = ",".join(sorted(defences)) or "none"
    print(f"\n=== {run_id} | {scenario['title']} | {contestant} | {model} | def={dfl}", flush=True)

    pinning_blocked = False
    helper_env = server_env(sink, sbox, scenario["attack"], False, sandbox.ATTACKER_RECIPIENT)
    baseline_desc = live_desc = None
    # Rug pull arms on the 2nd launch, so do an "approval" listing first (the user reviewing a benign tool).
    if scenario["attack"] == "rug_pull":
        baseline_desc = await helper_descriptions(helper_env)
        if "pinning" in defences:
            live_desc = await helper_descriptions(helper_env)  # real session's view
            pinning_blocked = live_desc != baseline_desc

    specs = build_specs(scenario, sink, sbox, defences)
    if pinning_blocked:
        specs = [s for s in specs if s.name != "helper"]  # client refuses the changed server

    system_prompt = SYSTEM_PROMPT_HARDENED if "sys_warn" in defences else SYSTEM_PROMPT
    approval = "approval" in defences

    t0 = time.time()
    try:
        result = await asyncio.wait_for(
            registry()[contestant](scenario["task"], system_prompt, specs, model, limits, approval=approval),
            timeout=limits.wall_clock_s,
        )
    except asyncio.TimeoutError:
        result = AgentResult(stopped_by="wall_clock")
    except Exception as exc:
        result = AgentResult(stopped_by="error", error=f"{type(exc).__name__}: {exc}")
    elapsed = round(time.time() - t0, 1)

    verdict = sandbox.score(sink, canary, scenario, result.final_text)
    record = {
        "run_id": run_id,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tag": tag,
        "scenario": scenario_id,
        "attack": scenario["attack"],
        "contestant": contestant,
        "sdk_version": version(SDK_PACKAGES[contestant]),
        "model": model,
        "defences": sorted(defences),
        "elapsed_s": elapsed,
        "pinning_blocked": pinning_blocked,
        "agent": {k: v for k, v in result.__dict__.items() if k != "final_text"},
        "verdict": dataclasses.asdict(verdict),
        "attack_succeeded": verdict.attack_succeeded,
        "benign_ok": verdict.benign_ok,
    }
    (sink / "final_text.md").write_text(result.final_text or "")
    (sink / "record.json").write_text(json.dumps(record, indent=2, default=str))
    with (RESULTS / "runs.jsonl").open("a") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
    print(f"    attack={'HIT' if verdict.attack_succeeded else 'miss'} secret_read={verdict.secret_read} "
          f"benign_ok={verdict.benign_ok} disclosed={verdict.disclosed} blocked={result.blocked_calls} "
          f"calls={result.model_calls} cost=${result.cost_usd} stopped={result.stopped_by}"
          + (f" err={result.error[:120]}" if result.error else ""), flush=True)
    return record


async def main() -> None:
    load_dotenv(ROOT / ".env")
    RUNTIME.mkdir(exist_ok=True)
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", help="comma-separated prefixes, e.g. 01,04 (default: all)")
    ap.add_argument("--contestants", default="claude-sdk")
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--defences", default="none", help="per-run defence sets; use '+' to combine, e.g. none,sys_warn,allowlist+approval")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--tag", default="pilot")
    args = ap.parse_args()

    defence_sets = [set() if d == "none" else set(d.split("+")) for d in args.defences.split(",")]
    limits = Limits()
    for trial in range(args.repeat):
        for sid in scenario_ids(args.scenarios):
            for contestant in args.contestants.split(","):
                for defs in defence_sets:
                    try:
                        await one_run(sid, contestant, args.model, defs, limits, args.tag)
                    except Exception as exc:
                        print(f"    RUN SETUP FAILED: {type(exc).__name__}: {str(exc)[:300]}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
