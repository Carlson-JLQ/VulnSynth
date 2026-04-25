#!/usr/bin/env python3

"""Minimal Codex CLI smoke test.

This script calls `codex exec` with a small prompt and prints:
- exit code / elapsed time
- raw stdout/stderr (optionally truncated)
- parsed JSONL event types summary
- extracted agent messages (if any)

It is designed to diagnose cases where Codex outputs only JSONL control frames
like thread.started / turn.started / error Reconnecting..., but never produces
agent_message / token_count.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


def _which_codex(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    p = shutil.which("codex")
    return p or "codex"


def _try_parse_json(line: str) -> Optional[dict]:
    line = (line or "").strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except Exception:
        return None


def _summarize_jsonl(stdout: str) -> Tuple[Dict[str, int], List[str], List[str]]:
    """Return (type_counts, agent_messages, error_messages)."""
    type_counts: Dict[str, int] = {}
    agent_messages: List[str] = []
    error_messages: List[str] = []

    for raw in (stdout or "").splitlines():
        obj = _try_parse_json(raw)
        if not isinstance(obj, dict):
            continue
        t = obj.get("type")
        if isinstance(t, str):
            type_counts[t] = type_counts.get(t, 0) + 1
        if t == "error" and isinstance(obj.get("message"), str):
            error_messages.append(obj["message"])

        # agent message shapes
        if t == "agent_message":
            msg = obj.get("message") or obj.get("text")
            if isinstance(msg, str) and msg.strip():
                agent_messages.append(msg.strip())
        msg_obj = obj.get("msg")
        if isinstance(msg_obj, dict) and msg_obj.get("type") == "agent_message":
            msg = msg_obj.get("message")
            if isinstance(msg, str) and msg.strip():
                agent_messages.append(msg.strip())
        item = obj.get("item")
        if isinstance(item, dict) and item.get("type") == "agent_message":
            msg = item.get("text")
            if isinstance(msg, str) and msg.strip():
                agent_messages.append(msg.strip())

    return type_counts, agent_messages, error_messages


def run_once(
    codex_path: str,
    prompt: str,
    model: Optional[str],
    bypass: bool,
    ephemeral: bool,
    disable_features: List[str],
    timeout_sec: int,
    cwd: Optional[str],
) -> Dict[str, Any]:
    cmd: List[str] = [codex_path, "exec", "--json"]
    if bypass:
        cmd.append("--dangerously-bypass-approvals-and-sandbox")
    if ephemeral:
        cmd.append("--ephemeral")
    for f in disable_features:
        cmd.extend(["--disable", f])
    if model:
        cmd.extend(["-m", model])

    t0 = time.time()
    try:
        p = subprocess.run(
            cmd,
            input=prompt.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
            cwd=cwd,
        )
        elapsed = time.time() - t0
        stdout = p.stdout.decode("utf-8", errors="replace")
        stderr = p.stderr.decode("utf-8", errors="replace")
        type_counts, agent_messages, error_messages = _summarize_jsonl(stdout)
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "elapsed_sec": elapsed,
            "stdout": stdout,
            "stderr": stderr,
            "jsonl_type_counts": type_counts,
            "agent_messages": agent_messages,
            "error_messages": error_messages,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        elapsed = time.time() - t0
        stdout = (e.stdout or b"").decode("utf-8", errors="replace")
        stderr = (e.stderr or b"").decode("utf-8", errors="replace")
        type_counts, agent_messages, error_messages = _summarize_jsonl(stdout)
        return {
            "cmd": cmd,
            "returncode": None,
            "elapsed_sec": elapsed,
            "stdout": stdout,
            "stderr": stderr,
            "jsonl_type_counts": type_counts,
            "agent_messages": agent_messages,
            "error_messages": error_messages,
            "timed_out": True,
        }


def _truncate(s: str, max_chars: int) -> str:
    if max_chars <= 0:
        return s
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + f"\n... (truncated, total={len(s)} chars)"


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke test calling Codex CLI (codex exec --json).")
    ap.add_argument("--codex", default=None, help="Path to codex binary (default: from PATH)")
    ap.add_argument("--model", default=None, help="Override model (e.g. gpt-5.4-2026-03-05)")
    ap.add_argument("--timeout", type=int, default=60, help="Timeout seconds per run")
    ap.add_argument("--cwd", default=None, help="Working directory for codex exec")
    ap.add_argument("--no-bypass", action="store_true", help="Do not pass dangerously bypass flag")
    ap.add_argument("--ephemeral", action="store_true", help="Pass --ephemeral")
    ap.add_argument("--disable", action="append", default=[], help="Disable feature flag (repeatable)")
    ap.add_argument("--max-chars", type=int, default=4000, help="Max chars to print for stdout/stderr")
    args = ap.parse_args()

    codex_path = _which_codex(args.codex)

    # Keep the task tiny and deterministic.
    prompt = (
        '你是一个 CLI 测试。\n'
        '请严格只输出一个 JSON 对象，不要输出 Markdown，不要输出解释：\n'
        '{"ok": true, "echo": "hello"}\n'
    )

    result = run_once(
        codex_path=codex_path,
        prompt=prompt,
        model=args.model,
        bypass=not args.no_bypass,
        ephemeral=args.ephemeral,
        disable_features=args.disable,
        timeout_sec=args.timeout,
        cwd=args.cwd,
    )

    print("=== codex exec smoke test ===")
    print("cmd:", " ".join(result["cmd"]))
    print("returncode:", result["returncode"], "timed_out:", result["timed_out"], "elapsed_sec:", f"{result['elapsed_sec']:.2f}")
    print("jsonl_type_counts:", result["jsonl_type_counts"])
    if result["error_messages"]:
        print("error_messages (tail):", result["error_messages"][-5:])
    if result["agent_messages"]:
        print("agent_messages (tail):", result["agent_messages"][-3:])

    print("--- STDOUT (truncated) ---")
    print(_truncate(result["stdout"], args.max_chars))
    print("--- STDERR (truncated) ---")
    print(_truncate(result["stderr"], args.max_chars))

    # Exit code: 0 if we saw agent message; 2 if timed out; 1 otherwise.
    if result["agent_messages"]:
        return 0
    if result["timed_out"]:
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

