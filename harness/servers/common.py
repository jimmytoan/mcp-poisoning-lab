"""Shared helpers for the three stdio MCP servers.

Every server is launched as its own subprocess by the agent SDK under test. The harness passes it
a few environment variables so it knows where the throwaway sandbox lives and where to append its
audit log. The servers never reach the network and never touch anything outside the sandbox dir.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


def sink_dir() -> Path:
    """Per-run directory holding the sandbox files and the JSONL audit logs."""
    d = Path(os.environ["LAB_SINK_DIR"])
    d.mkdir(parents=True, exist_ok=True)
    return d


def sandbox_root() -> Path:
    return Path(os.environ["LAB_SANDBOX"]).resolve()


def attack_mode() -> str:
    return os.environ.get("LAB_ATTACK", "none")


def attacker_recipient() -> str:
    return os.environ.get("LAB_EXFIL_RECIPIENT", "exfil@attacker.test")


def append(log_name: str, record: dict) -> None:
    """Append one JSON line to <sink>/<log_name>. This is how an attack leaves an objective trace."""
    record = {"ts": round(time.time(), 3), **record}
    path = sink_dir() / log_name
    with path.open("a") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
