#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

os.environ["ANONYMIZED_TELEMETRY"] = "false"

try:
    from .agent_backends import create_backend
    from .agent_backends import vulnsynth_prompts
except ImportError:
    from agent_backends import create_backend
    from agent_backends import vulnsynth_prompts

try:
    from .config import CVES_PATH, NVD_CACHE, VULNSYNTH_ROOT_DIR
except Exception:
    try:
        from config import CVES_PATH, NVD_CACHE, VULNSYNTH_ROOT_DIR
    except Exception:
        VULNSYNTH_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        CVES_PATH = os.path.join(VULNSYNTH_ROOT_DIR, "cves")
        NVD_CACHE = "nist_cve_cache"


LOGGER = logging.getLogger("vulnsynth")


def _read_patch_policy_yaml(policy_path: str) -> Dict[str, Any]:
    """Load the minimal patch policy YAML.

    Prefer PyYAML when available; otherwise fall back to a tiny parser that
    supports the limited structure used in `patch_policy.yaml`.
    """

    text = _read_text(policy_path)
    # First try PyYAML if installed.
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass

    # Minimal fallback parser for this repo's patch_policy.yaml.
    lines = [ln.rstrip("\n") for ln in text.splitlines()]
    policy: Dict[str, Any] = {"allowed_ops": [], "safety": {}, "files": {}}
    i = 0
    current_section: Optional[str] = None
    current_file: Optional[str] = None
    while i < len(lines):
        raw = lines[i]
        i += 1
        s = raw.strip()
        if not s or s.startswith("#"):
            continue

        if s.endswith(":") and not s.startswith("-"):
            key = s[:-1].strip()
            if key in ("allowed_ops", "safety", "files"):
                current_section = key
                current_file = None
                continue
            # file name under files:
            if current_section == "files" and key:
                current_file = key
                policy["files"].setdefault(current_file, {"allowed_paths": []})
                continue

        if current_section == "allowed_ops" and s.startswith("-"):
            policy["allowed_ops"].append(s.lstrip("-").strip())
            continue

        if current_section == "safety" and ":" in s:
            k, v = [p.strip() for p in s.split(":", 1)]
            if v.lower() in ("true", "false"):
                policy["safety"][k] = v.lower() == "true"
            else:
                try:
                    policy["safety"][k] = int(v)
                except Exception:
                    policy["safety"][k] = v
            continue

        # Allowed paths under files/<file>/allowed_paths
        if current_section == "files":
            if s.startswith("allowed_paths:"):
                continue
            if current_file and s.startswith("-"):
                policy["files"][current_file].setdefault("allowed_paths", []).append(s.lstrip("-").strip())
                continue

    return policy


def _json_pointer_unescape(seg: str) -> str:
    return seg.replace("~1", "/").replace("~0", "~")


def _split_json_pointer(ptr: str) -> List[str]:
    ptr = str(ptr or "").strip()
    if ptr == "":
        return []
    if not ptr.startswith("/"):
        raise ValueError(f"Invalid JSON Pointer (must start with '/'): {ptr!r}")
    parts = ptr.split("/")[1:]
    return [_json_pointer_unescape(p) for p in parts]


def _path_matches_pattern(pattern: str, path: str) -> bool:
    """Match JSON Pointer `path` against policy `pattern`.

    Policy patterns support `*` as a single-segment wildcard.
    """

    try:
        p_segs = _split_json_pointer(pattern)
        s_segs = _split_json_pointer(path)
    except Exception:
        return False
    if len(p_segs) != len(s_segs):
        return False
    for a, b in zip(p_segs, s_segs):
        if a == "*":
            continue
        if a != b:
            return False
    return True


def _get_at_pointer(doc: Any, ptr: str) -> Any:
    cur = doc
    for seg in _split_json_pointer(ptr):
        if isinstance(cur, list):
            idx = int(seg)
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur[seg]
        else:
            raise KeyError(f"Cannot traverse into non-container at segment {seg!r}")
    return cur


def _ensure_container_for_set(parent: Any, seg: str) -> None:
    # Best-effort helper: no-op if container already exists.
    if isinstance(parent, dict):
        parent.setdefault(seg, {})


def _set_at_pointer(doc: Any, ptr: str, value: Any, *, replace_with_many: bool = False) -> Any:
    segs = _split_json_pointer(ptr)
    if not segs:
        return value
    cur = doc
    for seg in segs[:-1]:
        if isinstance(cur, list):
            cur = cur[int(seg)]
        else:
            if not isinstance(cur, dict):
                raise KeyError(f"Cannot traverse into non-container at segment {seg!r}")
            if seg not in cur or not isinstance(cur[seg], (dict, list)):
                cur[seg] = {}
            cur = cur[seg]
    last = segs[-1]
    if isinstance(cur, list):
        idx = int(last)
        if replace_with_many and isinstance(value, list):
            cur[idx:idx + 1] = value
        else:
            cur[idx] = value
    elif isinstance(cur, dict):
        cur[last] = value
    else:
        raise KeyError(f"Cannot set into non-container at {ptr!r}")
    return doc


def _remove_at_pointer(doc: Any, ptr: str) -> Any:
    segs = _split_json_pointer(ptr)
    if not segs:
        return None
    cur = doc
    for seg in segs[:-1]:
        if isinstance(cur, list):
            cur = cur[int(seg)]
        else:
            cur = cur[seg]
    last = segs[-1]
    if isinstance(cur, list):
        del cur[int(last)]
    else:
        cur.pop(last, None)
    return doc


def _merge_value(existing: Any, incoming: Any) -> Any:
    if isinstance(existing, dict) and isinstance(incoming, dict):
        out = dict(existing)
        out.update(incoming)
        return out
    if isinstance(existing, list) and isinstance(incoming, list):
        out = list(existing)
        seen = set()
        for it in out:
            try:
                seen.add(json.dumps(it, sort_keys=True, ensure_ascii=False))
            except Exception:
                pass
        for it in incoming:
            key = None
            try:
                key = json.dumps(it, sort_keys=True, ensure_ascii=False)
            except Exception:
                key = None
            if key is not None and key in seen:
                continue
            out.append(it)
            if key is not None:
                seen.add(key)
        return out
    return incoming


def _cleanup_orphan_mcp_processes() -> Dict[str, int]:
    """Best-effort cleanup for orphaned MCP/LSP processes.

    We only target processes whose parent pid is 1 (orphaned), to avoid killing
    actively used servers started by the current interactive session.
    """

    killed = {"codeql_mcp": 0, "codeql_lsp": 0, "chroma_mcp": 0}
    try:
        out = subprocess.check_output(["ps", "-eo", "pid=,ppid=,cmd="], text=True)
    except Exception:
        return killed

    targets: List[Tuple[int, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except Exception:
            continue
        cmd = parts[2]
        if ppid != 1:
            continue

        if "codeql-lsp-mcp/dist/index.js" in cmd or "codeql-mcp/dist/index.js" in cmd:
            targets.append((pid, "codeql_mcp"))
        elif "codeql execute language-server" in cmd:
            targets.append((pid, "codeql_lsp"))
        elif "chroma-mcp" in cmd:
            targets.append((pid, "chroma_mcp"))

    for pid, kind in targets:
        try:
            os.kill(pid, signal.SIGTERM)
            killed[kind] += 1
        except Exception:
            pass

    # Give processes a moment to exit, then force-kill if still alive.
    time.sleep(0.5)
    for pid, kind in targets:
        try:
            os.kill(pid, 0)
        except Exception:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    return killed

GLOBAL_COLLECTIONS = {
    "codeql_ql_reference": {
        "scope": "global",
        "language": "any",
        "content_type": ["reference", "syntax", "predicate", "class"],
        "priority": 2,
    },
    "cwe_data": {
        "scope": "global",
        "language": "any",
        "content_type": ["weakness", "taxonomy", "security_semantics"],
        "priority": 3,
    },
}

LANGUAGE_COLLECTIONS = {
    "java": [
        {
            "name": "java_codeql_stdlib",
            "scope": "language_specific",
            "language": "java",
            "content_type": ["stdlib", "api", "class", "predicate"],
            "priority": 1,
        },
        {
            "name": "java_codeql_language_guides",
            "scope": "language_specific",
            "language": "java",
            "content_type": ["guide", "idiom", "pattern"],
            "priority": 2,
        },
        {
            "name": "java_codeql_local_queries",
            "scope": "language_specific",
            "language": "java",
            "content_type": ["query", "pattern", "example"],
            "priority": 1,
        },
    ],
    "cpp": [
        {
            "name": "cpp_codeql_stdlib",
            "scope": "language_specific",
            "language": "cpp",
            "content_type": ["stdlib", "api", "class", "predicate"],
            "priority": 1,
        },
        {
            "name": "cpp_codeql_language_guides",
            "scope": "language_specific",
            "language": "cpp",
            "content_type": ["guide", "idiom", "pattern"],
            "priority": 2,
        },
        {
            "name": "cpp_codeql_local_queries",
            "scope": "language_specific",
            "language": "cpp",
            "content_type": ["query", "pattern", "example"],
            "priority": 1,
        },
    ],
}


@dataclass
class VulnSynthTask:
    cve_id: str
    cve_dir: str
    repo_path: str
    diff_path: str
    fix_commit_diff: str
    cve_description: str = ""
    nvd_cache: str = NVD_CACHE


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _write_yaml_like_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")


def _slugify(value: str, max_len: int = 48) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
    return slug[:max_len] if len(slug) > max_len else (slug or "item")


def _maybe_load_cve_description(cve_id: str) -> str:
    fix_info = os.path.join(VULNSYNTH_ROOT_DIR, "data", "fix_info.csv")
    if not os.path.exists(fix_info):
        return ""
    try:
        with open(fix_info, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            rows = [row for row in reader if row.get("cve_id") == cve_id]
        if not rows:
            return ""
        first = rows[0]
        parts = []
        for key in ("github_username", "github_repository_name", "file", "class", "method", "signature"):
            value = (first.get(key) or "").strip()
            if value:
                parts.append(f"{key}: {value}")
        return "; ".join(parts)
    except Exception:
        return ""


def _preprocess_diff(diff_content: str, max_chars: int = 60000) -> str:
    if len(diff_content) <= max_chars:
        return diff_content
    head = diff_content[: max_chars // 2]
    tail = diff_content[-max_chars // 2 :]
    return (
        head
        + "\n\n... [diff truncated by VulnSynth plan agent for prompt size control] ...\n\n"
        + tail
    )


def _find_repo_root(cve_dir: str, cve_id: str) -> str:
    candidates = []
    for entry in os.scandir(cve_dir):
        if not entry.is_dir():
            continue
        name = entry.name
        if name.startswith(f"{cve_id}-"):
            continue
        if name.startswith("."):
            continue
        score = 0
        if os.path.isdir(os.path.join(entry.path, ".git")):
            score += 10
        for marker in ("pom.xml", "build.gradle", "settings.gradle", "package.json", "Cargo.toml", "Makefile"):
            if os.path.exists(os.path.join(entry.path, marker)):
                score += 3
        candidates.append((score, entry.path))

    if not candidates:
        raise FileNotFoundError(f"Could not identify repository root under {cve_dir}")

    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][1]


def discover_cve_paths(cve_id: str) -> tuple[str, str, str]:
    cve_dir = os.path.join(CVES_PATH, cve_id)
    if not os.path.isdir(cve_dir):
        raise FileNotFoundError(f"CVE directory not found: {cve_dir}")

    diff_path = os.path.join(cve_dir, f"{cve_id}.diff")
    if not os.path.exists(diff_path):
        raise FileNotFoundError(f"Diff file not found: {diff_path}")

    repo_path = _find_repo_root(cve_dir, cve_id)
    return cve_dir, repo_path, diff_path


def _extract_json_object(text: str) -> Dict[str, Any]:
    text = text.strip()
    if not text:
        raise ValueError("Empty model output")

    # Prefer fenced JSON blocks.
    fenced = re.findall(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    candidates = fenced or []

    # If no fenced blocks, try direct parse first.
    if not candidates:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Scan for balanced top-level JSON objects.
    if not candidates:
        starts = [i for i, ch in enumerate(text) if ch == "{"]
        for start in starts:
            depth = 0
            in_string = False
            escape = False
            for idx in range(start, len(text)):
                ch = text[idx]
                if in_string:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_string = False
                    continue
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[start : idx + 1])
                        break

    for candidate in sorted(candidates, key=len, reverse=True):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    raise ValueError("Unable to extract valid JSON object from model output")


def compile_codeql_query(
    query_path: str,
    language: str,
    codeql_path: str,
    output_dir: str,
    artifact_prefix: str = "compile",
) -> Dict[str, Any]:
    if not os.path.exists(codeql_path):
        raise FileNotFoundError(f"CodeQL CLI not found: {codeql_path}")

    dependencies = {
        "java": "codeql/java-all",
        "cpp": "codeql/cpp-all",
    }
    dependency = dependencies.get(language)
    if dependency is None:
        raise ValueError(f"Unsupported language for compile check: {language}")

    qlpacks_path = os.path.join(os.path.dirname(codeql_path), "qlpacks")
    compile_dir = tempfile.mkdtemp(prefix="vulnsynth_compile_", dir=output_dir)
    compile_query_path = os.path.abspath(os.path.join(compile_dir, os.path.basename(query_path)))
    _write_text(compile_query_path, _read_text(query_path))
    _write_yaml_like_text(
        os.path.join(compile_dir, "qlpack.yml"),
        f"name: vulnsynth/generated\nversion: 0.0.1\ndependencies:\n  {dependency}: '*'\n",
    )

    import subprocess

    cmd = [
        codeql_path,
        "query",
        "compile",
        "--search-path",
        qlpacks_path,
        os.path.basename(compile_query_path),
    ]
    proc = subprocess.run(
        cmd,
        cwd=compile_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    result = {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "query_path": query_path,
        "codeql_path": codeql_path,
        "compile_dir": compile_dir,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "command": cmd,
    }
    _write_json(os.path.join(output_dir, f"{artifact_prefix}_result.json"), result)
    _write_text(os.path.join(output_dir, f"{artifact_prefix}_stdout.log"), proc.stdout)
    _write_text(os.path.join(output_dir, f"{artifact_prefix}_stderr.log"), proc.stderr)
    return result


def _append_jsonl(path: str, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _discover_codeql_db_paths(cve_id: str) -> tuple[str, str]:
    """Return (vuln_db_path, fixed_db_path) for a CVE if present."""
    cve_dir = os.path.join(CVES_PATH, cve_id)
    vuln_db = os.path.join(cve_dir, f"{cve_id}-vul")
    fixed_db = os.path.join(cve_dir, f"{cve_id}-fix")
    if not os.path.isdir(vuln_db):
        raise FileNotFoundError(f"Vulnerable CodeQL database directory not found: {vuln_db}")
    if not os.path.isdir(fixed_db):
        raise FileNotFoundError(f"Fixed CodeQL database directory not found: {fixed_db}")
    return vuln_db, fixed_db


def _count_csv_rows(csv_path: str) -> int:
    try:
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            return 0
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            # subtract header
            lines = f.readlines()
        return max(0, len(lines) - 1)
    except Exception:
        return 0


def _tail(text: str, max_lines: int = 80) -> str:
    lines = (text or "").splitlines()
    return "\n".join(lines[-max_lines:])


def run_codeql_query_on_database(
    *,
    query_path: str,
    database_path: str,
    database_type: str,
    codeql_path: str,
    output_dir: str,
    artifact_prefix: str,
) -> Dict[str, Any]:
    """Run CodeQL query on a database and emit BQRS+CSV+SARIF artifacts."""
    import subprocess

    base = f"{artifact_prefix}_{database_type}"
    bqrs_path = os.path.join(output_dir, f"{base}.bqrs")
    csv_path = os.path.join(output_dir, f"{base}.csv")
    sarif_path = os.path.join(output_dir, f"{base}.sarif")

    run_cmd = [
        codeql_path,
        "query",
        "run",
        "--database",
        database_path,
        "--output",
        bqrs_path,
        "--",
        query_path,
    ]
    run_proc = subprocess.run(
        run_cmd,
        cwd=output_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    decode_cmd = [
        codeql_path,
        "bqrs",
        "decode",
        "--format=csv",
        f"--output={csv_path}",
        bqrs_path,
    ]
    decode_proc = None
    if run_proc.returncode == 0:
        decode_proc = subprocess.run(
            decode_cmd,
            cwd=output_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    analyze_cmd = [
        codeql_path,
        "database",
        "analyze",
        database_path,
        query_path,
        "--format=sarif-latest",
        "--output",
        sarif_path,
        "--rerun",
    ]
    analyze_proc = None
    if run_proc.returncode == 0:
        analyze_proc = subprocess.run(
            analyze_cmd,
            cwd=output_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    # Best-effort cache cleanup to avoid lock issues.
    cleanup_cmd = [codeql_path, "database", "cleanup", database_path, "--cache-cleanup=clear"]
    cleanup_proc = subprocess.run(
        cleanup_cmd,
        cwd=output_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    num_results = _count_csv_rows(csv_path)
    result = {
        "success": run_proc.returncode == 0,
        "database_type": database_type,
        "database_path": database_path,
        "query_path": query_path,
        "bqrs_path": bqrs_path,
        "csv_path": csv_path,
        "sarif_path": sarif_path,
        "num_results": num_results,
        "run": {
            "returncode": run_proc.returncode,
            "command": run_cmd,
            "stdout_tail": _tail(run_proc.stdout),
            "stderr_tail": _tail(run_proc.stderr),
        },
        "decode": None,
        "analyze": None,
        "cleanup": {
            "returncode": cleanup_proc.returncode,
            "command": cleanup_cmd,
            "stdout_tail": _tail(cleanup_proc.stdout),
            "stderr_tail": _tail(cleanup_proc.stderr),
        },
    }
    if decode_proc is not None:
        result["decode"] = {
            "returncode": decode_proc.returncode,
            "command": decode_cmd,
            "stdout_tail": _tail(decode_proc.stdout),
            "stderr_tail": _tail(decode_proc.stderr),
        }
    if analyze_proc is not None:
        result["analyze"] = {
            "returncode": analyze_proc.returncode,
            "command": analyze_cmd,
            "stdout_tail": _tail(analyze_proc.stdout),
            "stderr_tail": _tail(analyze_proc.stderr),
        }
    return result


def _infer_language_from_ir(l1: Dict[str, Any], repo_path: str) -> str:
    metadata = l1.get("metadata", {})
    language = str(metadata.get("language", "")).strip().lower()
    if language:
        return language
    if os.path.exists(os.path.join(repo_path, "pom.xml")) or os.path.exists(os.path.join(repo_path, "build.gradle")):
        return "java"
    if any(os.path.exists(os.path.join(repo_path, marker)) for marker in ("CMakeLists.txt", "compile_commands.json")):
        return "cpp"
    return "java"


def _build_collection_registry(language: str, nvd_cache: str) -> Dict[str, list[Dict[str, Any]]]:
    global_collections = [
        {
            "name": nvd_cache,
            "scope": "case_specific",
            "language": "any",
            "content_type": ["cve", "advisory", "description"],
            "priority": 0,
        },
    ]
    for name, data in GLOBAL_COLLECTIONS.items():
        item = dict(data)
        item["name"] = name
        global_collections.append(item)
    language_collections = LANGUAGE_COLLECTIONS.get(language, [])
    return {
        "global": global_collections,
        "language_specific": language_collections,
    }


def _build_query_views(step: Dict[str, Any]) -> Dict[str, str]:
    raw_hints = step.get("retrieval_hints", {})
    hints: Dict[str, Any] = raw_hints if isinstance(raw_hints, dict) else {}

    # Backward/forward compatibility: some L3 plans use `retrieval_hints` as a
    # list of free-form strings rather than a structured dict.
    if not hints and isinstance(raw_hints, (list, tuple)):
        merged: list[str] = []
        for it in raw_hints:
            s = str(it).strip()
            if not s:
                continue
            merged.append(s)
            # Prefer explicit identifiers if present (often in backticks).
            try:
                merged.extend([t.strip() for t in re.findall(r"`([^`]+)`", s) if t.strip()])
            except Exception:
                pass
        hints = {"keywords": merged}
    elif not hints and isinstance(raw_hints, str) and raw_hints.strip():
        hints = {"keywords": [raw_hints.strip()]}

    def _as_list(v: Any) -> list:
        if v is None:
            return []
        if isinstance(v, list):
            return v
        if isinstance(v, tuple):
            return list(v)
        if isinstance(v, str):
            return [v]
        return [v]

    keywords = _as_list(hints.get("keywords", []))
    classes = _as_list(hints.get("candidate_classes", []))
    predicates = _as_list(hints.get("candidate_predicates", []))
    patterns = _as_list(hints.get("reference_query_patterns", []))
    semantic_base = step.get("description") or step.get("goal") or step.get("semantic_unit") or ""
    return {
        "semantic_query": semantic_base.strip(),
        "keyword_query": ", ".join(str(v).strip() for v in keywords if str(v).strip()),
        "symbol_query": " ".join(
            str(v).strip() for v in [*classes, *predicates] if str(v).strip()
        ),
        "pattern_query": "; ".join(str(v).strip() for v in patterns if str(v).strip()),
    }


def _infer_retrieval_targets(step: Dict[str, Any]) -> Dict[str, bool]:
    fragment_type = step.get("fragment_type", "")
    return {
        "need_cve_context": True,
        "need_cwe_semantics": fragment_type in ("where_clause", "select_clause"),
        "need_reference_queries": True,
        "need_classes": fragment_type in ("predicate", "helper_class"),
        "need_predicates": True,
        "need_guides": True,
    }


def build_step_retrieval_plan(step: Dict[str, Any], language: str, nvd_cache: str) -> Dict[str, Any]:
    registry = _build_collection_registry(language, nvd_cache)
    query_views = _build_query_views(step)
    targets = _infer_retrieval_targets(step)
    collection_queries: Dict[str, list[str]] = {
        nvd_cache: ["semantic_query"],
        "codeql_ql_reference": ["symbol_query", "pattern_query"],
        "cwe_data": ["semantic_query", "keyword_query"],
    }
    if language == "java":
        collection_queries.update(
            {
                "java_codeql_stdlib": ["symbol_query"],
                "java_codeql_language_guides": ["semantic_query", "pattern_query"],
                "java_codeql_local_queries": ["keyword_query", "pattern_query"],
            }
        )
    elif language == "cpp":
        collection_queries.update(
            {
                "cpp_codeql_stdlib": ["symbol_query"],
                "cpp_codeql_language_guides": ["semantic_query", "pattern_query"],
                "cpp_codeql_local_queries": ["keyword_query", "pattern_query"],
            }
        )

    # Allowlist the exact collections the model may query for this step.
    # This mitigates cross-language drift when other similarly-named collections exist.
    allowed_collection_names = sorted({str(k) for k in collection_queries.keys() if str(k).strip()})

    # Optional per-collection metadata filters for Chroma queries.
    # Not all collections have a `language` metadata field (for example `codeql_ql_reference`),
    # so only provide filters where we know ingestion typically sets them.
    collection_where_filters: Dict[str, Dict[str, Any]] = {}
    if language == "java":
        for cname in ("java_codeql_stdlib", "java_codeql_language_guides", "java_codeql_local_queries"):
            if cname in collection_queries:
                collection_where_filters[cname] = {"language": "java"}
    elif language == "cpp":
        for cname in ("cpp_codeql_stdlib", "cpp_codeql_language_guides", "cpp_codeql_local_queries"):
            if cname in collection_queries:
                collection_where_filters[cname] = {"language": "cpp"}

    step_id = step.get("step_id") or step.get("id")
    return {
        "step_id": step_id,
        "language": language,
        "retrieval_targets": targets,
        "global_collections": registry["global"],
        "language_collections": registry["language_specific"],
        "query_views": query_views,
        "collection_query_map": collection_queries,
        "allowed_collection_names": allowed_collection_names,
        "collection_where_filters": collection_where_filters,
    }


class VulnSynthPlanAgent:
    def __init__(
        self,
        working_dir: Optional[str] = None,
        agent: str = "codex",
        model: str = "gpt-5",
        ablation_mode: str = "full",
        codex_use_local_config: bool = True,
    ):
        self.working_dir = working_dir or VULNSYNTH_ROOT_DIR
        self.logger = LOGGER
        self.backend = create_backend(
            agent,
            model,
            self.logger,
            ablation_mode=ablation_mode,
            use_local_config=codex_use_local_config,
        )

    @staticmethod
    def _compact_text(s: Any, *, max_len: int) -> Any:
        if not isinstance(s, str):
            return s
        s = s.strip()
        if len(s) <= max_len:
            return s
        return s[: max(0, max_len - 1)] + "…"

    @classmethod
    def _compact_fact_list(cls, xs: Any, *, max_items: int, max_fact_len: int = 400) -> list:
        if not isinstance(xs, list):
            return []
        out: list = []
        for it in xs[: max(0, int(max_items))]:
            if isinstance(it, dict):
                keep = {}
                for k in ("file", "line", "fact", "diff_file", "source"):
                    if k in it:
                        v = it.get(k)
                        if k == "fact":
                            v = cls._compact_text(v, max_len=max_fact_len)
                        keep[k] = v
                out.append(keep or it)
            else:
                out.append(it)
        return out

    @classmethod
    def _compact_l1_for_prompt(cls, l1: Any) -> Any:
        if not isinstance(l1, dict):
            return l1
        return {
            "layer": l1.get("layer"),
            "cve_id": l1.get("cve_id"),
            "repo_path": l1.get("repo_path"),
            "diff_path": l1.get("diff_path"),
            "pattern_summary": cls._compact_text(l1.get("pattern_summary"), max_len=1200),
            "code_facts": cls._compact_fact_list(l1.get("code_facts"), max_items=20),
            "patch_facts": cls._compact_fact_list(l1.get("patch_facts"), max_items=12),
            "environment_facts": cls._compact_fact_list(l1.get("environment_facts"), max_items=10),
        }

    @classmethod
    def _compact_l2_for_prompt(cls, l2: Any) -> Any:
        if not isinstance(l2, dict):
            return l2
        return {
            "layer": l2.get("layer"),
            "schema_version": l2.get("schema_version"),
            "cve_id": l2.get("cve_id"),
            "pattern_type": l2.get("pattern_type"),
            "summary": cls._compact_text(l2.get("summary"), max_len=1600),
            "constraints": cls._compact_fact_list(l2.get("constraints"), max_items=20),
            "guards_and_conditions": cls._compact_fact_list(l2.get("guards_and_conditions"), max_items=20),
            "reporting": (l2.get("reporting") if isinstance(l2.get("reporting"), dict) else {}),
        }

    async def _run_stage(
        self,
        stage_name: str,
        prompt: str,
        output_dir: str,
    ) -> Dict[str, Any]:
        prompt_path = os.path.join(output_dir, f"{stage_name}_prompt.md")
        _write_text(prompt_path, prompt)

        env = os.environ.copy()

        # Avoid long-running Coco calls from blocking the loop indefinitely.
        # Plan stages can be retrieval-heavy; keep bounded.
        if stage_name in ("stage1_l1", "stage2_l2", "stage3_l3"):
            # Plan stages can still be retrieval-heavy on larger repos.
            env.setdefault("COCO_QUERY_TIMEOUT_SEC", "600")

        # Default: avoid Coco session persistence to prevent conversation bloat.
        # VulnSynth includes full context in each prompt, so sessions are unnecessary.
        use_sessions = str(env.get("VULNSYNTH_USE_COCO_SESSIONS", "0")).strip() in ("1", "true", "True")
        if not use_sessions:
            env.pop("COCO_SESSION_ID", None)
            env.pop("COCO_RESUME", None)
        else:
            # Multi-session support for Coco: allow a stable base session id and derive
            # a role-specific session for plan stages.
            base_session = str(env.get("COCO_SESSION_ID_BASE", "") or env.get("COCO_SESSION_ID", "")).strip()
            if base_session:
                env["COCO_SESSION_ID"] = f"{base_session}::plan"

        def _looks_like_coco_trace(obj: Any) -> bool:
            return isinstance(obj, dict) and (
                ("agent_states" in obj and "session_id" in obj) or ("stats" in obj and "agent_states" in obj)
            )

        def _validate_contract(stage: str, parsed_obj: Any) -> None:
            """Fail fast when the model returns a trace / wrong-shaped output."""
            if _looks_like_coco_trace(parsed_obj):
                raise RuntimeError(f"{stage} returned a Coco trace instead of the required JSON object")
            if not isinstance(parsed_obj, dict):
                raise RuntimeError(f"{stage} did not return a JSON object")

            expected_layer = {
                "stage1_l1": "L1_fact",
                "stage2_l2": "L2_schema_ir",
                "stage3_l3": "L3_query_construction_steps",
            }.get(stage)
            if expected_layer is not None:
                layer = str(parsed_obj.get("layer", "") or "").strip()
                if layer != expected_layer:
                    raise RuntimeError(f"{stage} returned layer={layer!r}, expected {expected_layer!r}")

            if stage == "stage1_l1":
                ps = str(parsed_obj.get("pattern_summary", "") or "").strip()
                if not ps:
                    raise RuntimeError("stage1_l1 missing non-empty pattern_summary")
            if stage == "compose_final_query":
                qc = str(parsed_obj.get("query_code", "") or "").strip()
                if not qc:
                    raise RuntimeError("compose_final_query produced empty query_code")

        async def _exec_once(p: str) -> Dict[str, Any]:
            result = await self.backend.execute_prompt(
                prompt=p,
                env=env,
                cwd=self.working_dir,
                phase_name=stage_name,
            )

            stdout_path = os.path.join(output_dir, f"{stage_name}_stdout.jsonl")
            stderr_path = os.path.join(output_dir, f"{stage_name}_stderr.log")
            _write_text(stdout_path, result.get("stdout", ""))
            _write_text(stderr_path, result.get("stderr", ""))

            if result.get("returncode", 1) != 0:
                raise RuntimeError(
                    f"{stage_name} failed with return code {result.get('returncode')}: "
                    f"{result.get('stderr', '').strip()}"
                )

            text_output = self.backend.extract_text_output(result.get("stdout", ""))
            _write_text(os.path.join(output_dir, f"{stage_name}_assistant.txt"), text_output)
            parsed = _extract_json_object(text_output)
            _write_json(os.path.join(output_dir, f"{stage_name}_parsed.json"), parsed)
            _validate_contract(stage_name, parsed)
            return parsed

        # Some models may attempt to use interactive planning tools or return a full
        # trace instead of the required JSON. Retry once with a stricter reminder.
        try:
            return await _exec_once(prompt)
        except Exception as e:
            self.logger.warning(f"{stage_name}: first attempt failed validation: {e}")
            stricter = (
                prompt
                + "\n\n# STRICT OUTPUT REMINDER\n"
                + "- Do NOT call `TodoWrite`.\n"
                + "- Do NOT output tool traces or system messages.\n"
                + "- Return ONLY the single JSON object required by the Output Contract.\n"
            )
            return await _exec_once(stricter)

    async def analyze(self, cve_id: str, output_root: str = "src/IR") -> Dict[str, str]:
        cve_dir, repo_path, diff_path = discover_cve_paths(cve_id)
        diff_content = _read_text(diff_path)
        processed_diff = _preprocess_diff(diff_content)

        task = VulnSynthTask(
            cve_id=cve_id,
            cve_dir=cve_dir,
            repo_path=repo_path,
            diff_path=diff_path,
            fix_commit_diff=processed_diff,
            cve_description=_maybe_load_cve_description(cve_id),
        )

        output_dir = os.path.join(self.working_dir, output_root, cve_id)
        os.makedirs(output_dir, exist_ok=True)

        # Default base session id for standalone plan runs.
        os.environ.setdefault("COCO_SESSION_ID_BASE", f"vulnsynth-{cve_id}")

        self.logger.info(f"Using repository root: {repo_path}")
        self.logger.info(f"Writing IR outputs to: {output_dir}")

        self.backend.setup_workspace(output_dir, task)

        metadata = {
            "cve_id": cve_id,
            "repo_path": repo_path,
            "diff_path": diff_path,
            "output_dir": output_dir,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "backend": "codex",
            "model": self.backend.model,
            "ablation_mode": self.backend.ablation_mode,
        }
        _write_json(os.path.join(output_dir, "metadata.json"), metadata)

        self.logger.info("Stage 1/3: generating L1 facts")
        l1 = await self._run_stage(
            "stage1_l1",
            vulnsynth_prompts.build_l1_prompt(task),
            output_dir,
        )
        # Safety: keep the L1 object compact enough to fit within OS ARG_MAX when
        # embedding into later prompts.
        l1 = self._compact_l1_for_prompt(l1)
        _write_json(os.path.join(output_dir, "cve_facts.json"), l1)

        self.logger.info("Stage 2/3: generating L2 schema IR")
        l2 = await self._run_stage(
            "stage2_l2",
            vulnsynth_prompts.build_l2_prompt(task, json.dumps(l1, indent=2, ensure_ascii=False)),
            output_dir,
        )
        l2 = self._compact_l2_for_prompt(l2)
        _write_json(os.path.join(output_dir, "codeql_schema_ir.json"), l2)

        self.logger.info("Stage 3/3: generating L3 query construction steps")
        l3 = await self._run_stage(
            "stage3_l3",
            vulnsynth_prompts.build_l3_prompt(
                task,
                json.dumps(l1, indent=2, ensure_ascii=False),
                json.dumps(l2, indent=2, ensure_ascii=False),
            ),
            output_dir,
        )
        _write_json(os.path.join(output_dir, "codeql_logic_steps.json"), l3)

        return {
            "output_dir": output_dir,
            "l1_path": os.path.join(output_dir, "cve_facts.json"),
            "l2_path": os.path.join(output_dir, "codeql_schema_ir.json"),
            "l3_path": os.path.join(output_dir, "codeql_logic_steps.json"),
        }

    async def analyze_partial(
        self,
        cve_id: str,
        output_root: str = "src/IR",
        *,
        rerun_l1: bool = False,
        rerun_l2: bool = False,
        rerun_l3: bool = False,
    ) -> Dict[str, str]:
        """Selective rerun of plan stages.

        - If rerun_l1: regenerate L1 (and implicitly forces rerun_l2/l3 unless explicitly false downstream).
        - If rerun_l2: regenerate L2 using current (possibly regenerated) L1.
        - If rerun_l3: regenerate L3 using current (possibly regenerated) L1/L2.
        """
        cve_dir, repo_path, diff_path = discover_cve_paths(cve_id)
        diff_content = _read_text(diff_path)
        processed_diff = _preprocess_diff(diff_content)
        task = VulnSynthTask(
            cve_id=cve_id,
            cve_dir=cve_dir,
            repo_path=repo_path,
            diff_path=diff_path,
            fix_commit_diff=processed_diff,
            cve_description=_maybe_load_cve_description(cve_id),
        )

        output_dir = os.path.join(self.working_dir, output_root, cve_id)
        os.makedirs(output_dir, exist_ok=True)

        # Default base session id for standalone plan runs.
        os.environ.setdefault("COCO_SESSION_ID_BASE", f"vulnsynth-{cve_id}")
        self.backend.setup_workspace(output_dir, task)

        l1_path = os.path.join(output_dir, "cve_facts.json")
        l2_path = os.path.join(output_dir, "codeql_schema_ir.json")
        l3_path = os.path.join(output_dir, "codeql_logic_steps.json")

        l1: Dict[str, Any]
        l2: Dict[str, Any]

        if rerun_l1 or not os.path.exists(l1_path):
            self.logger.info("Plan partial: regenerating L1")
            l1 = await self._run_stage("stage1_l1", vulnsynth_prompts.build_l1_prompt(task), output_dir)
            l1 = self._compact_l1_for_prompt(l1)
            _write_json(l1_path, l1)
        else:
            l1 = _read_json(l1_path)

        # Even when loading from disk, ensure L1 used for prompting is compact.
        l1 = self._compact_l1_for_prompt(l1)

        if rerun_l2 or rerun_l1 or not os.path.exists(l2_path):
            self.logger.info("Plan partial: regenerating L2")
            l2 = await self._run_stage(
                "stage2_l2",
                vulnsynth_prompts.build_l2_prompt(task, json.dumps(l1, indent=2, ensure_ascii=False)),
                output_dir,
            )
            l2 = self._compact_l2_for_prompt(l2)
            _write_json(l2_path, l2)
        else:
            l2 = _read_json(l2_path)

        l2 = self._compact_l2_for_prompt(l2)

        if rerun_l3 or rerun_l2 or rerun_l1 or not os.path.exists(l3_path):
            self.logger.info("Plan partial: regenerating L3")
            l3 = await self._run_stage(
                "stage3_l3",
                vulnsynth_prompts.build_l3_prompt(
                    task,
                    json.dumps(l1, indent=2, ensure_ascii=False),
                    json.dumps(l2, indent=2, ensure_ascii=False),
                ),
                output_dir,
            )
            _write_json(l3_path, l3)

        return {"output_dir": output_dir, "l1_path": l1_path, "l2_path": l2_path, "l3_path": l3_path}


class VulnSynthGenAgent:
    def __init__(
        self,
        working_dir: Optional[str] = None,
        agent: str = "codex",
        model: str = "gpt-5",
        ablation_mode: str = "full",
        codex_use_local_config: bool = True,
    ):
        self.working_dir = working_dir or VULNSYNTH_ROOT_DIR
        self.logger = LOGGER
        self.backend = create_backend(
            agent,
            model,
            self.logger,
            ablation_mode=ablation_mode,
            use_local_config=codex_use_local_config,
        )

    async def _run_stage(self, stage_name: str, prompt: str, output_dir: str) -> Dict[str, Any]:
        prompt_path = os.path.join(output_dir, f"{stage_name}_prompt.md")
        _write_text(prompt_path, prompt)

        env = os.environ.copy()

        # Avoid long-running Coco calls from blocking the feedback loop indefinitely.
        # Coco honors --query-timeout via COCO_QUERY_TIMEOUT_SEC.
        if stage_name == "diagnose":
            env.setdefault("COCO_QUERY_TIMEOUT_SEC", "180")
        elif stage_name == "compose_final_query":
            # Composition can be retrieval-heavy and may require multiple tool calls.
            # Keep bounded, but allow more headroom than fragment generation.
            env.setdefault("COCO_QUERY_TIMEOUT_SEC", "600")
        elif stage_name.startswith("gen_step_"):
            # Fragment generation should not hang indefinitely (e.g., MCP/tool stalls).
            # Keep this high enough for retrieval-heavy steps but bounded.
            env.setdefault("COCO_QUERY_TIMEOUT_SEC", "600")

        # Default: avoid Coco session persistence to prevent conversation bloat.
        # VulnSynth includes full context in each prompt, so sessions are unnecessary.
        use_sessions = str(env.get("VULNSYNTH_USE_COCO_SESSIONS", "0")).strip() in ("1", "true", "True")
        if not use_sessions:
            env.pop("COCO_SESSION_ID", None)
            env.pop("COCO_RESUME", None)
        else:
            # Multi-session support for Coco: derive dedicated sessions for fragment
            # generation vs final composition.
            base_session = str(env.get("COCO_SESSION_ID_BASE", "") or env.get("COCO_SESSION_ID", "")).strip()
            if base_session:
                role = "compose" if stage_name == "compose_final_query" else "gen"
                env["COCO_SESSION_ID"] = f"{base_session}::{role}"

            # Start each stage from a clean session to prevent prompt bloat.
            try:
                sid = str(env.get("COCO_SESSION_ID", "")).strip()
                if sid:
                    self.backend.cleanup_sessions([sid])
            except Exception:
                pass

        def _expected_contract_keys() -> Optional[set[str]]:
            if stage_name.startswith("gen_step_"):
                return {
                    "step_id",
                    "fragment_type",
                    "summary",
                    "required_imports",
                    "defines_symbols",
                    "depends_on_symbols",
                    "codeql_fragment",
                    "notes",
                }
            if stage_name == "compose_final_query":
                return {"query_file_name", "query_code"}
            return None

        def _looks_like_coco_trace_obj(obj: Any) -> bool:
            # A trace has orchestration keys, not the stage's output contract.
            return isinstance(obj, dict) and (
                ("agent_states" in obj and "session_id" in obj)
                or ("agent_states" in obj and "stats" in obj)
                or ("stats" in obj and "session_id" in obj)
            )

        def _validate_contract(parsed: Any) -> Optional[str]:
            if not isinstance(parsed, dict):
                return "output is not a JSON object"
            if _looks_like_coco_trace_obj(parsed):
                return "output looks like a Coco trace (no final assistant answer)"
            expected = _expected_contract_keys()
            if expected is None:
                return None
            missing = [k for k in sorted(expected) if k not in parsed]
            if missing:
                return f"missing required keys: {', '.join(missing)}"
            return None

        async def _exec_once(*, phase_tag: str, prompt_text: str) -> Dict[str, Any]:
            result = await self.backend.execute_prompt(
                prompt=prompt_text,
                env=env,
                cwd=self.working_dir,
                phase_name=phase_tag,
            )
            stdout_path = os.path.join(output_dir, f"{phase_tag}_stdout.jsonl")
            stderr_path = os.path.join(output_dir, f"{phase_tag}_stderr.log")
            _write_text(stdout_path, result.get("stdout", ""))
            _write_text(stderr_path, result.get("stderr", ""))

            if result.get("returncode", 1) != 0:
                raise RuntimeError(
                    f"{phase_tag} failed with return code {result.get('returncode')}: "
                    f"{result.get('stderr', '').strip()}"
                )

            text_output = self.backend.extract_text_output(result.get("stdout", ""))
            _write_text(os.path.join(output_dir, f"{phase_tag}_assistant.txt"), text_output)
            result["_text_output"] = text_output
            return result

        def _extract_code_block(text: str) -> str:
            # Prefer fenced CodeQL blocks, but tolerate generic fences.
            m = re.search(r"```(?:ql|codeql)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
            if m:
                return (m.group(1) or "").strip()
            return text.strip()

        def _infer_required_imports(code: str) -> list:
            imports: list[str] = []
            for line in (code or "").splitlines():
                s = line.strip()
                if s.startswith("import "):
                    # Keep the whole import line (minus trailing semicolon).
                    imports.append(s.rstrip(";").strip())
            # de-dup preserving order
            seen = set()
            out: list[str] = []
            for it in imports:
                if it in seen:
                    continue
                seen.add(it)
                out.append(it)
            return out

        def _salvage_non_json_output() -> Optional[Dict[str, Any]]:
            """Best-effort salvage when model returns CodeQL instead of JSON.

            This commonly happens for fragment steps where the model outputs a fenced
            CodeQL snippet. We wrap it into the required JSON contract using step.json.
            """
            # Compose stage: model may output a raw query; wrap it into final_query.json.
            if stage_name == "compose_final_query":
                code = _extract_code_block(text_output)
                if not code:
                    return None
                cve_id = "generated"
                meta_path = os.path.join(output_dir, "metadata.json")
                try:
                    meta = _read_json(meta_path) if os.path.exists(meta_path) else {}
                    if isinstance(meta, dict) and meta.get("cve_id"):
                        cve_id = str(meta.get("cve_id"))
                except Exception:
                    pass
                return {
                    "query_file_name": f"{cve_id}.ql",
                    "query_code": code.rstrip() + "\n",
                    "notes": [
                        "Auto-salvaged: model returned CodeQL query instead of the required JSON object.",
                    ],
                }

            step_path = os.path.join(output_dir, "step.json")
            if not os.path.exists(step_path):
                return None
            try:
                step_obj = _read_json(step_path)
            except Exception:
                return None
            if not isinstance(step_obj, dict):
                return None

            code = _extract_code_block(text_output)
            if not code:
                return None

            step_id = step_obj.get("step_id") or stage_name
            fragment_type = step_obj.get("fragment_type") or "predicate"
            requires = step_obj.get("requires_symbols")
            produces = step_obj.get("produces_symbols")
            return {
                "step_id": step_id,
                "fragment_type": fragment_type,
                "summary": f"Auto-salvaged non-JSON output for {step_id}",
                "required_imports": _infer_required_imports(code),
                "defines_symbols": produces if isinstance(produces, list) else [],
                "depends_on_symbols": requires if isinstance(requires, list) else [],
                "codeql_fragment": code.rstrip() + "\n",
                "notes": [
                    "Auto-salvaged: model returned CodeQL snippet instead of the required JSON object.",
                ],
            }

        # Retry loop:
        # - If Coco returns only a trace (common on timeouts), treat as failure and retry.
        # - If JSON parses but does not match the stage's output contract, retry.
        # - On retry, append a strict "output only JSON" reminder while preserving full context.
        last_error: str = ""
        max_attempts = 3
        for attempt in range(max_attempts):
            phase_tag = stage_name if attempt == 0 else f"{stage_name}_retry{attempt}"
            prompt_text = prompt
            if attempt > 0:
                prompt_text = (
                    prompt
                    + "\n\n# Output Repair (STRICT)\n"
                    + "Return EXACTLY ONE JSON object and NOTHING ELSE. No markdown fences.\n"
                    + "The JSON object MUST conform to the Output Contract described above.\n"
                )

                # Give retries extra headroom (still bounded).
                try:
                    base = int(str(env.get("COCO_QUERY_TIMEOUT_SEC", "0") or "0"))
                    if base > 0:
                        env["COCO_QUERY_TIMEOUT_SEC"] = str(max(base, 720))
                except Exception:
                    pass

            result = await _exec_once(phase_tag=phase_tag, prompt_text=prompt_text)
            text_output = str(result.get("_text_output", "") or "")

            if not text_output.strip():
                last_error = "empty assistant output (likely Coco query timeout / trace-only response)"
                continue

            # Normal path: parse JSON output.
            try:
                parsed = _extract_json_object(text_output)
            except Exception as e:
                # Persist the parse failure for debugging.
                _write_text(
                    os.path.join(output_dir, f"{phase_tag}_parse_error.log"),
                    f"{type(e).__name__}: {e}\n\n{text_output}\n",
                )

                salvaged = _salvage_non_json_output()
                if salvaged is not None:
                    err = _validate_contract(salvaged)
                    if err is None:
                        parsed = salvaged
                    else:
                        last_error = f"salvaged output failed contract: {err}"
                        continue
                else:
                    last_error = f"failed to parse model output as JSON: {type(e).__name__}: {e}"
                    continue

            err = _validate_contract(parsed)
            if err is not None:
                # Save what we got for diagnosis, but retry.
                try:
                    _write_json(os.path.join(output_dir, f"{phase_tag}_parsed.json"), parsed)
                except Exception:
                    pass
                last_error = err
                continue

            # Success: persist canonical artifacts for downstream stages.
            _write_text(os.path.join(output_dir, f"{stage_name}_assistant.txt"), text_output)
            _write_json(os.path.join(output_dir, f"{stage_name}_parsed.json"), parsed)
            _write_text(os.path.join(output_dir, f"{stage_name}_stdout.jsonl"), result.get("stdout", ""))
            _write_text(os.path.join(output_dir, f"{stage_name}_stderr.log"), result.get("stderr", ""))
            return parsed

        raise RuntimeError(f"{stage_name} did not produce valid output after {max_attempts} attempts: {last_error}")

    async def generate(
        self,
        cve_id: str,
        ir_root: str = "src/IR",
        generation_subdir: str = "generated_query",
        *,
        rerun_steps: Optional[List[str]] = None,
        rerun_composer: bool = True,
        reuse_existing_fragments: bool = True,
    ) -> Dict[str, str]:
        cve_dir, repo_path, diff_path = discover_cve_paths(cve_id)
        ir_case_dir = os.path.join(self.working_dir, ir_root, cve_id)
        l1_path = os.path.join(ir_case_dir, "cve_facts.json")
        l2_path = os.path.join(ir_case_dir, "codeql_schema_ir.json")
        l3_path = os.path.join(ir_case_dir, "codeql_logic_steps.json")

        for required_path in (l1_path, l2_path, l3_path):
            if not os.path.exists(required_path):
                raise FileNotFoundError(f"Required IR file not found: {required_path}")

        l1 = _read_json(l1_path)
        l2 = _read_json(l2_path)
        l3 = _read_json(l3_path)
        steps = l3.get("steps", [])
        if not steps:
            raise ValueError(f"No L3 steps found in {l3_path}")

        task = VulnSynthTask(
            cve_id=cve_id,
            cve_dir=cve_dir,
            repo_path=repo_path,
            diff_path=diff_path,
            fix_commit_diff=_preprocess_diff(_read_text(diff_path)),
            cve_description=_maybe_load_cve_description(cve_id),
        )

        language = _infer_language_from_ir(l1, repo_path)

        # Keep prompts within model/context limits.
        # The raw L1/L2 can be very large (hundreds of KB) which causes the composer
        # stage to time out before it can emit JSON. Fragments should carry most of
        # the required query logic; keep only high-signal fields here.
        def _compact_fact_list(xs: Any, *, max_items: int) -> list:
            if not isinstance(xs, list):
                return []
            out: list = []
            for it in xs[: max(0, int(max_items))]:
                if isinstance(it, dict):
                    # Preserve common keys but drop unexpected large blobs.
                    keep = {k: it.get(k) for k in ("file", "line", "fact", "diff_file", "source") if k in it}
                    out.append(keep or it)
                else:
                    out.append(it)
            return out

        l1_compact: Dict[str, Any] = {}
        if isinstance(l1, dict):
            l1_compact = {
                "layer": l1.get("layer"),
                "cve_id": l1.get("cve_id"),
                "repo_path": l1.get("repo_path"),
                "diff_path": l1.get("diff_path"),
                "pattern_summary": l1.get("pattern_summary"),
                "code_facts": _compact_fact_list(l1.get("code_facts"), max_items=12),
                "patch_facts": _compact_fact_list(l1.get("patch_facts"), max_items=8),
                "environment_facts": _compact_fact_list(l1.get("environment_facts"), max_items=6),
            }

        l2_compact: Dict[str, Any] = {}
        if isinstance(l2, dict):
            # Keep only schema summary + key constraints for the pattern.
            l2_compact = {
                "layer": l2.get("layer"),
                "schema_version": l2.get("schema_version"),
                "cve_id": l2.get("cve_id"),
                "pattern_type": l2.get("pattern_type"),
                "summary": l2.get("summary"),
                "constraints": _compact_fact_list(l2.get("constraints"), max_items=10),
                "reporting": (l2.get("reporting") if isinstance(l2.get("reporting"), dict) else {}),
            }

        l1_json = json.dumps(l1_compact or l1, indent=2, ensure_ascii=False)
        l2_json = json.dumps(l2_compact or l2, indent=2, ensure_ascii=False)

        # Default base session id for standalone gen runs.
        os.environ.setdefault("COCO_SESSION_ID_BASE", f"vulnsynth-{cve_id}")
        output_dir = os.path.join(ir_case_dir, generation_subdir)
        fragments_dir = os.path.join(output_dir, "fragments")
        os.makedirs(fragments_dir, exist_ok=True)
        self.backend.setup_workspace(output_dir, task)

        metadata = {
            "cve_id": cve_id,
            "language": language,
            "repo_path": repo_path,
            "ir_root": ir_case_dir,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "backend": "codex",
            "model": self.backend.model,
            "ablation_mode": self.backend.ablation_mode,
        }
        _write_json(os.path.join(output_dir, "metadata.json"), metadata)

        # Keep fragment prompts within model token limits.
        # The full L3 step list can be large and is mostly redundant because the
        # current step JSON includes the concrete step contract.
        l3_compact: Dict[str, Any] = {
            "layer": l3.get("layer"),
            "plan_version": l3.get("plan_version"),
            "case_id": l3.get("case_id"),
            "goal": l3.get("goal"),
        }
        try:
            steps_list = l3.get("steps")
            if isinstance(steps_list, list):
                l3_compact["steps_overview"] = [
                    {
                        "step_id": (s or {}).get("step_id") or (s or {}).get("id"),
                        "semantic_unit": (s or {}).get("semantic_unit"),
                    }
                    for s in steps_list
                    if isinstance(s, dict)
                ]
        except Exception:
            pass
        l3_json = json.dumps(l3_compact, indent=2, ensure_ascii=False)

        rerun_steps_set = set(rerun_steps or [])

        def _forbidden_codeql_symbol(language: str, code: str) -> Optional[str]:
            """Return the first forbidden symbol found in `code`, else None.

            This is a lightweight guardrail to prevent cross-version / cross-language
            CodeQL API hallucinations from entering the fragment bundle.
            """
            if not isinstance(code, str):
                return None
            # CodeQL Java in CodeQL 2.23.x uses `MethodCall` (not `MethodAccess`).
            if language == "java" and re.search(r"\bMethodAccess\b", code):
                return "MethodAccess"
            return None

        fragment_bundle: Dict[str, Any] = {
            "case_id": cve_id,
            "language": language,
            "fragments": [],
        }

        fragment_refs: List[Dict[str, Any]] = []

        existing_bundle_path = os.path.join(output_dir, "fragment_bundle.json")
        existing_bundle: Optional[dict] = None
        if reuse_existing_fragments and os.path.exists(existing_bundle_path):
            try:
                loaded = _read_json(existing_bundle_path)
                if isinstance(loaded, dict):
                    existing_bundle = loaded
            except Exception:
                existing_bundle = None

        # Always preserve any out-of-band loop control fields from the existing bundle.
        if isinstance(existing_bundle, dict):
            for k in ("feedback", "feedback_history", "regen_steps"):
                if k in existing_bundle:
                    fragment_bundle[k] = existing_bundle[k]

        # If we are in compose-only mode and we have an existing bundle, reuse its fragments.
        if reuse_existing_fragments and not rerun_steps_set and isinstance(existing_bundle, dict):
            if isinstance(existing_bundle.get("fragments"), list):
                fragment_bundle["fragments"] = existing_bundle.get("fragments", [])

        need_generate_any_fragments = not fragment_bundle.get("fragments") or bool(rerun_steps_set)

        if need_generate_any_fragments:
            # Rebuild fragment list deterministically in step order.
            fragment_bundle["fragments"] = []

        for index, step in enumerate(steps, start=1):
            step_id = step.get("step_id") or step.get("id") or f"step_{index}"
            slug = _slugify(step_id)
            retrieval_plan = build_step_retrieval_plan(step, language, task.nvd_cache)
            step_output_dir = os.path.join(fragments_dir, f"{index:02d}_{slug}")
            os.makedirs(step_output_dir, exist_ok=True)
            _write_json(os.path.join(step_output_dir, "retrieval_plan.json"), retrieval_plan)
            # Normalize step identifier for downstream prompts and patch targeting.
            step_for_prompt = dict(step)
            step_for_prompt.setdefault("step_id", step_id)
            _write_json(os.path.join(step_output_dir, "step.json"), step_for_prompt)

            fragment_refs.append(
                {
                    "index": index,
                    "step_id": step_id,
                    "dir": step_output_dir,
                    "fragment_json_path": os.path.join(step_output_dir, "fragment.json"),
                    "qlfrag_path": os.path.join(step_output_dir, "fragment.qlfrag"),
                }
            )

            fragment_path = os.path.join(step_output_dir, "fragment.json")
            should_rerun = (
                ("*" in rerun_steps_set)
                or (step_id in rerun_steps_set)
                or (not os.path.exists(fragment_path))
            )

            if not need_generate_any_fragments:
                # We are in compose-only mode and already have a bundle.
                continue

            fragment: Dict[str, Any]
            if (not should_rerun) and reuse_existing_fragments:
                try:
                    fragment = _read_json(fragment_path)
                    if not isinstance(fragment, dict):
                        raise ValueError("fragment.json is not a dict")

                    # Guardrail: avoid reusing a Coco trace (or any malformed fragment)
                    # as if it were a valid step fragment.
                    required = {
                        "step_id",
                        "fragment_type",
                        "summary",
                        "required_imports",
                        "defines_symbols",
                        "depends_on_symbols",
                        "codeql_fragment",
                        "notes",
                    }
                    if any(k not in fragment for k in required):
                        raise ValueError("fragment.json is missing required contract keys")
                    if not str(fragment.get("codeql_fragment", "") or "").strip():
                        raise ValueError("fragment.json has empty codeql_fragment")

                    forbidden = _forbidden_codeql_symbol(language, str(fragment.get("codeql_fragment", "") or ""))
                    if forbidden:
                        raise ValueError(f"fragment.json contains forbidden CodeQL symbol: {forbidden}")
                except Exception:
                    should_rerun = True

            if should_rerun:
                loop_feedback = ""
                try:
                    fb = fragment_bundle.get("feedback")
                    if fb is not None:
                        loop_feedback = json.dumps(fb, indent=2, ensure_ascii=False)
                except Exception:
                    loop_feedback = ""
                base_prompt = vulnsynth_prompts.build_fragment_prompt(
                    task,
                    l1_json,
                    l2_json,
                    l3_json,
                    json.dumps(step_for_prompt, indent=2, ensure_ascii=False),
                    json.dumps(retrieval_plan, indent=2, ensure_ascii=False),
                    language,
                    loop_feedback_json=loop_feedback,
                )

                async def _gen_once(extra_guidance: str = "") -> Dict[str, Any]:
                    p = base_prompt
                    if extra_guidance.strip():
                        p = (
                            p
                            + "\n\n# EXTRA GENERATION GUARDRAIL\n"
                            + extra_guidance.strip()
                            + "\n"
                        )
                    return await self._run_stage(
                        f"gen_step_{index:02d}_{slug}",
                        p,
                        step_output_dir,
                    )

                fragment = await _gen_once()

                # Lightweight semantic guardrail: if the generated fragment contains
                # a known-invalid symbol for this language, regenerate once with an
                # explicit correction.
                forbidden = _forbidden_codeql_symbol(language, str(fragment.get("codeql_fragment", "") or ""))
                if forbidden:
                    fragment = await _gen_once(
                        f"- The generated fragment used `{forbidden}`, which is not available in this environment.\n"
                        f"- For Java, use `MethodCall` for method invocation expressions (not `{forbidden}`).\n"
                        "- Re-run retrieval using ONLY the collections listed in the Retrieval Plan allowlist, then regenerate the fragment."
                    )

                _write_json(fragment_path, fragment)
                fragment_code = str(fragment.get("codeql_fragment", "")).rstrip() + "\n"
                _write_text(os.path.join(step_output_dir, "fragment.qlfrag"), fragment_code)

            fragment_bundle["fragments"].append(fragment)

        fragment_bundle_path = os.path.join(output_dir, "fragment_bundle.json")
        _write_json(fragment_bundle_path, fragment_bundle)

        final_query_json_path = os.path.join(output_dir, "final_query.json")
        if rerun_composer:
            loop_feedback = ""
            try:
                fb = fragment_bundle.get("feedback")
                if fb is not None:
                    loop_feedback = json.dumps(fb, indent=2, ensure_ascii=False)
            except Exception:
                loop_feedback = ""
            fragment_index_json = json.dumps(
                {
                    "fragment_bundle_path": fragment_bundle_path,
                    "fragments_dir": fragments_dir,
                    "fragment_refs": fragment_refs,
                },
                indent=2,
                ensure_ascii=False,
            )
            compose_prompt = vulnsynth_prompts.build_query_composition_prompt(
                task,
                l1_json,
                l2_json,
                l3_json,
                fragment_index_json,
                language,
                loop_feedback_json=loop_feedback,
            )
            final_query = await self._run_stage("compose_final_query", compose_prompt, output_dir)

            # If the composer introduces a known-invalid symbol for this language,
            # retry once with an explicit correction note.
            try:
                qc0 = str((final_query or {}).get("query_code", "") or "")
            except Exception:
                qc0 = ""
            forbidden = _forbidden_codeql_symbol(language, qc0)
            if forbidden:
                self.logger.warning(
                    f"compose_final_query used forbidden CodeQL symbol {forbidden}; retrying once with stricter guidance"
                )
                final_query = await self._run_stage(
                    "compose_final_query",
                    compose_prompt
                    + "\n\n# COMPOSITION GUARDRAIL\n"
                    + f"- The composed query used `{forbidden}`, which is not available in this environment.\n"
                    + "- For Java, use `MethodCall` for method invocation expressions (not `MethodAccess`).\n",
                    output_dir,
                )
            # Guardrail: if composition fails (timeout/trace output), avoid clobbering a
            # previously good query with an empty one.
            try:
                qc = str((final_query or {}).get("query_code", "") or "").strip()
            except Exception:
                qc = ""
            if not qc and os.path.exists(final_query_json_path):
                try:
                    prev = _read_json(final_query_json_path)
                    prev_qc = str((prev or {}).get("query_code", "") or "").strip() if isinstance(prev, dict) else ""
                    if prev_qc:
                        self.logger.warning(
                            "compose_final_query produced empty query_code; preserving previous final_query.json"
                        )
                        final_query = prev
                except Exception:
                    pass
            _write_json(final_query_json_path, final_query)
        else:
            final_query = _read_json(final_query_json_path) if os.path.exists(final_query_json_path) else {}

        query_file_name = final_query.get("query_file_name") or f"{cve_id.lower()}_generated.ql"
        if not str(query_file_name).endswith(".ql"):
            query_file_name = f"{query_file_name}.ql"
        query_path = os.path.join(output_dir, query_file_name)
        _write_text(query_path, str(final_query.get("query_code", "")).rstrip() + "\n")

        return {
            "output_dir": output_dir,
            "fragments_dir": fragments_dir,
            "fragment_bundle_path": fragment_bundle_path,
            "final_query_json_path": os.path.join(output_dir, "final_query.json"),
            "final_query_path": query_path,
        }


class VulnSynthValidAgent:
    """Validates a generated query by compiling and executing it on vuln/fix databases."""

    def __init__(self, working_dir: Optional[str] = None):
        self.working_dir = working_dir or VULNSYNTH_ROOT_DIR
        self.logger = LOGGER

    async def validate(
        self,
        cve_id: str,
        ir_root: str = "src/IR",
        generation_subdir: str = "generated_query",
        codeql_path: str = "",
        *,
        output_dir: Optional[str] = None,
        artifact_prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not codeql_path:
            raise ValueError("--codeql-path (or env CODEQL_PATH) must be set for valid mode")

        ir_case_dir = os.path.join(self.working_dir, ir_root, cve_id)
        l1_path = os.path.join(ir_case_dir, "cve_facts.json")
        if not os.path.exists(l1_path):
            raise FileNotFoundError(f"Required IR file not found: {l1_path}")
        l1 = _read_json(l1_path)

        # Locate generated query directory.
        gen_dir = os.path.join(ir_case_dir, generation_subdir)
        if not os.path.isdir(gen_dir):
            raise FileNotFoundError(f"Generated query directory not found: {gen_dir}")

        final_query_json_path = os.path.join(gen_dir, "final_query.json")
        if not os.path.exists(final_query_json_path):
            raise FileNotFoundError(f"final_query.json not found: {final_query_json_path}")
        final_query = _read_json(final_query_json_path)
        query_file_name = final_query.get("query_file_name") or f"{cve_id}.ql"
        if not str(query_file_name).endswith(".ql"):
            query_file_name = f"{query_file_name}.ql"
        query_path = os.path.join(gen_dir, query_file_name)

        # Keep `final_query.json` (source of truth) and the materialized `.ql` file in sync.
        # This matters when the feedback loop applies patches directly to `final_query.json`.
        try:
            query_code = str((final_query or {}).get("query_code", "") or "")
        except Exception:
            query_code = ""
        query_code = query_code.rstrip() + "\n" if query_code else ""
        if query_code.strip():
            # Always (re)materialize the `.ql` file from `final_query.json`.
            try:
                existing = _read_text(query_path) if os.path.exists(query_path) else ""
                if existing.strip() != query_code.strip():
                    _write_text(query_path, query_code)
            except Exception:
                _write_text(query_path, query_code)
        elif not os.path.exists(query_path):
            # Fallback: if the file name differs, pick the first .ql in gen_dir.
            ql_files = [p for p in os.listdir(gen_dir) if p.endswith(".ql")]
            if not ql_files:
                raise FileNotFoundError(f"No .ql file found in {gen_dir}")
            query_path = os.path.join(gen_dir, sorted(ql_files)[0])

        # Discover vuln/fix DBs.
        vuln_db, fixed_db = _discover_codeql_db_paths(cve_id)

        cve_dir, repo_path, diff_path = discover_cve_paths(cve_id)
        language = _infer_language_from_ir(l1, repo_path)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        artifact_prefix = artifact_prefix or f"validation_{timestamp}"
        out_dir = output_dir or gen_dir

        compile_result = compile_codeql_query(
            query_path,
            language,
            codeql_path,
            out_dir,
            artifact_prefix=f"{artifact_prefix}_compile",
        )

        vuln_result = run_codeql_query_on_database(
            query_path=query_path,
            database_path=vuln_db,
            database_type="vulnerable",
            codeql_path=codeql_path,
            output_dir=out_dir,
            artifact_prefix=f"{artifact_prefix}",
        )
        fixed_result = run_codeql_query_on_database(
            query_path=query_path,
            database_path=fixed_db,
            database_type="fixed",
            codeql_path=codeql_path,
            output_dir=out_dir,
            artifact_prefix=f"{artifact_prefix}",
        )

        evaluation: Dict[str, Any] = {
            "success": False,
            "vulnerable": None,
            "fixed": None,
            "recall_method": None,
            "recall_file": None,
            "error": None,
        }

        # Effect evaluation: compare SARIF results against FIX_INFO targets.
        try:
            # `src/evaluation.py` reads CODEQL_PATH from env at import time.
            if codeql_path and not os.environ.get("CODEQL_PATH"):
                os.environ["CODEQL_PATH"] = codeql_path
            try:
                from src.evaluation import QueryEvaluator
            except ImportError:
                from evaluation import QueryEvaluator

            vuln_sarif = str(vuln_result.get("sarif_path") or "")
            fixed_sarif = str(fixed_result.get("sarif_path") or "")
            if vuln_sarif and os.path.exists(vuln_sarif):
                vuln_eval_path = os.path.join(out_dir, f"{artifact_prefix}_vulnerable_eval.json")
                evaluator = QueryEvaluator(
                    input_dir=out_dir,
                    cve_id=cve_id,
                    diff_file=diff_path,
                    final_output_json_path=vuln_eval_path,
                    database_path=vuln_db,
                    logger=self.logger,
                )
                evaluation["vulnerable"] = evaluator.evaluate_sarif_result(vuln_sarif, query_path, vuln_db)

            if fixed_sarif and os.path.exists(fixed_sarif):
                fixed_eval_path = os.path.join(out_dir, f"{artifact_prefix}_fixed_eval.json")
                evaluator = QueryEvaluator(
                    input_dir=out_dir,
                    cve_id=cve_id,
                    diff_file=diff_path,
                    final_output_json_path=fixed_eval_path,
                    database_path=fixed_db,
                    logger=self.logger,
                )
                evaluation["fixed"] = evaluator.evaluate_sarif_result(fixed_sarif, query_path, fixed_db)

            v = evaluation.get("vulnerable") or {}
            evaluation["recall_method"] = bool(v.get("recall_method"))
            evaluation["recall_file"] = bool(v.get("recall_file"))
            evaluation["success"] = True
        except Exception as e:
            evaluation["error"] = str(e)

        summary = {
            "cve_id": cve_id,
            "ir_case_dir": ir_case_dir,
            "generated_query_dir": gen_dir,
            "query_path": query_path,
            "language": language,
            "codeql_path": codeql_path,
            "vuln_db": vuln_db,
            "fixed_db": fixed_db,
            "compile": {
                "success": bool(compile_result.get("success")),
                "result_path": os.path.join(gen_dir, f"{artifact_prefix}_compile_result.json"),
                "stdout_path": os.path.join(gen_dir, f"{artifact_prefix}_compile_stdout.log"),
                "stderr_path": os.path.join(gen_dir, f"{artifact_prefix}_compile_stderr.log"),
                "stderr_tail": _tail(str(compile_result.get("stderr", ""))),
            },
            "run": {
                "vulnerable": vuln_result,
                "fixed": fixed_result,
                "delta": {
                    "vulnerable_results": vuln_result.get("num_results", 0),
                    "fixed_results": fixed_result.get("num_results", 0),
                },
            },
            "evaluation": evaluation,
        }

        summary_path = os.path.join(out_dir, f"{artifact_prefix}_summary.json")
        _write_json(summary_path, summary)
        return {
            "summary_path": summary_path,
            "query_path": query_path,
            "generated_query_dir": gen_dir,
        }


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _load_case_ir_paths(ir_case_dir: str) -> tuple[str, str, str]:
    return (
        os.path.join(ir_case_dir, "cve_facts.json"),
        os.path.join(ir_case_dir, "codeql_schema_ir.json"),
        os.path.join(ir_case_dir, "codeql_logic_steps.json"),
    )


def _load_case_ir(ir_case_dir: str) -> tuple[dict, dict, dict]:
    l1_path, l2_path, l3_path = _load_case_ir_paths(ir_case_dir)
    for p in (l1_path, l2_path, l3_path):
        if not os.path.exists(p):
            raise FileNotFoundError(f"Required IR file not found: {p}")
    return _read_json(l1_path), _read_json(l2_path), _read_json(l3_path)


def _write_case_ir(ir_case_dir: str, l1: dict, l2: dict, l3: dict) -> None:
    l1_path, l2_path, l3_path = _load_case_ir_paths(ir_case_dir)
    _write_json(l1_path, l1)
    _write_json(l2_path, l2)
    _write_json(l3_path, l3)


class FailureAnalyzer:
    """Failure analyzer following IR_FEEDBACK_LOOP_DESIGN-cn.md (MVP+).

    Produces:
    - failure_report.json fields
    - classified_failures with normalized failure_type taxonomy
    - primary_failure_type
    """

    def analyze(self, *, case_id: str, iteration: int, validation_summary: dict) -> dict:
        compile_ok = bool(validation_summary.get("compile", {}).get("success"))
        run = validation_summary.get("run", {})
        vuln = run.get("vulnerable", {})
        fixed = run.get("fixed", {})

        vuln_results = int(run.get("delta", {}).get("vulnerable_results", vuln.get("num_results", 0)) or 0)
        fixed_results = int(run.get("delta", {}).get("fixed_results", fixed.get("num_results", 0)) or 0)

        compile_stderr = str(validation_summary.get("compile", {}).get("stderr_tail", ""))
        compile_stderr_l = compile_stderr.lower()

        vuln_run_rc = int(vuln.get("run", {}).get("returncode", 0) or 0)
        fixed_run_rc = int(fixed.get("run", {}).get("returncode", 0) or 0)
        vuln_analyze_rc = int(vuln.get("analyze", {}).get("returncode", 0) or 0) if vuln.get("analyze") else 0
        fixed_analyze_rc = int(fixed.get("analyze", {}).get("returncode", 0) or 0) if fixed.get("analyze") else 0

        classified: List[dict] = []

        def _add(ft: str, sev: str, conf: float, evidence: List[str], scopes: List[str]) -> None:
            classified.append(
                {
                    "failure_type": ft,
                    "severity": sev,
                    "confidence": conf,
                    "evidence": evidence,
                    "suggested_update_scope": scopes,
                }
            )

        # 5.1 Compile-class failures
        if not compile_ok:
            if "syntax error" in compile_stderr_l:
                _add(
                    "syntax_error",
                    "high",
                    0.9,
                    ["compile failed", "compile stderr contains 'syntax error'"],
                    ["composer"],
                )
            elif "wrong number of arguments" in compile_stderr_l or "expects" in compile_stderr_l and "argument" in compile_stderr_l:
                _add(
                    "wrong_predicate_arity",
                    "high",
                    0.8,
                    ["compile failed", "compile stderr indicates wrong predicate arity"],
                    ["fragment", "composer"],
                )
            elif "type error" in compile_stderr_l or "incompatible" in compile_stderr_l:
                _add(
                    "wrong_type_constraint",
                    "high",
                    0.75,
                    ["compile failed", "compile stderr indicates type error"],
                    ["fragment", "l2"],
                )
            elif "duplicate" in compile_stderr_l and "defined" in compile_stderr_l:
                _add(
                    "fragment_composition_conflict",
                    "high",
                    0.75,
                    ["compile failed", "compile stderr indicates duplicate definition"],
                    ["composer", "l3"],
                )
            elif "could not resolve" in compile_stderr_l or "cannot be resolved" in compile_stderr_l:
                if "import" in compile_stderr_l or "module" in compile_stderr_l:
                    _add(
                        "missing_import",
                        "high",
                        0.85,
                        ["compile stderr indicates missing import/module"],
                        ["composer", "fragment"],
                    )
                else:
                    _add(
                        "unresolved_codeql_symbol",
                        "high",
                        0.85,
                        ["compile stderr indicates unresolved symbol"],
                        ["fragment", "l3_retrieval"],
                    )
            else:
                _add(
                    "syntax_error",
                    "high",
                    0.6,
                    ["compile failed", "fallback classify as syntax_error"],
                    ["composer"],
                )

        # 5.2 Execution-class failures
        if compile_ok:
            if vuln_run_rc != 0 or fixed_run_rc != 0:
                _add(
                    "query_runtime_failure",
                    "high",
                    0.8,
                    [f"vuln run rc={vuln_run_rc}", f"fixed run rc={fixed_run_rc}"],
                    ["fragment", "composer"],
                )
            if vuln_analyze_rc != 0 or fixed_analyze_rc != 0:
                _add(
                    "database_analyze_failure",
                    "medium",
                    0.7,
                    [f"vuln analyze rc={vuln_analyze_rc}", f"fixed analyze rc={fixed_analyze_rc}"],
                    ["environment"],
                )

        # 5.3 Effect-class failures (only when compile succeeded)
        if compile_ok:
            evaluation = validation_summary.get("evaluation", {}) or {}
            # Prefer evaluator-based target hit signals when available.
            eval_recall_method = evaluation.get("recall_method")
            eval_recall_file = evaluation.get("recall_file")

            if vuln_results == 0:
                _add(
                    "empty_result_on_vulnerable",
                    "high",
                    0.8,
                    ["compile success", "vulnerable results == 0"],
                    ["l3", "fragment", "composer"],
                )
            elif (eval_recall_method is False) and (eval_recall_file is False):
                # Has results but misses known fixed locations -> likely target miss.
                _add(
                    "target_miss_on_vulnerable",
                    "high",
                    0.75,
                    ["compile success", "vulnerable results > 0", "evaluation recall_file=false and recall_method=false"],
                    ["l2", "l3", "fragment", "composer"],
                )
            elif fixed_results > 0:
                _add(
                    "false_positive_on_fixed",
                    "high",
                    0.8,
                    ["fixed results > 0"],
                    ["l2", "l3", "fragment", "composer"],
                )

        def _severity_rank(sev: str) -> int:
            return {"high": 3, "medium": 2, "low": 1}.get(str(sev).lower(), 0)

        primary = None
        if classified:
            primary = sorted(
                classified,
                key=lambda item: (-_severity_rank(item.get("severity", "")), -float(item.get("confidence", 0.0))),
            )[0].get("failure_type")
        else:
            # Fallback: taxonomy couldn't explain the failure.
            classified.append(
                {
                    "failure_type": "unknown_failure",
                    "severity": "low",
                    "confidence": 0.3,
                    "evidence": [
                        "no known failure pattern matched",
                        f"compile_ok={compile_ok}",
                        f"vuln_results={vuln_results}",
                        f"fixed_results={fixed_results}",
                    ],
                    "suggested_update_scope": ["fallback"],
                }
            )
            primary = "unknown_failure"

        report = {
            "case_id": case_id,
            "iteration": iteration,
            "query_path": validation_summary.get("query_path"),
            "compile": {
                "success": compile_ok,
                "stderr_summary": compile_stderr.strip(),
            },
            "execution": {
                "ran_on_vulnerable": bool(vuln.get("success", False)),
                "ran_on_fixed": bool(fixed.get("success", False)),
                "vulnerable_results": vuln_results,
                "fixed_results": fixed_results,
            },
            "evaluation": {
                "recall_method": (validation_summary.get("evaluation", {}) or {}).get("recall_method"),
                "recall_file": (validation_summary.get("evaluation", {}) or {}).get("recall_file"),
                "false_positive_on_fixed": fixed_results > 0,
            },
            "primary_failure_type": primary,
            "classified_failures": classified,
        }
        return report


class UpdateEngine:
    """Applies policy-constrained patches to IR artifacts.

    This follows AGENT_DIAGNOSIS_POLICY_REPAIR-cn.md:
    - Diagnoser proposes minimal patches
    - UpdateEngine validates patches against patch_policy.yaml
    - UpdateEngine applies only whitelisted (file, op, path)
    """

    def __init__(self, policy_path: Optional[str] = None):
        self.policy_path = policy_path or os.path.join(VULNSYNTH_ROOT_DIR, "patch_policy.yaml")
        self._policy_cache: Optional[Dict[str, Any]] = None

    def _policy(self) -> Dict[str, Any]:
        if self._policy_cache is None:
            self._policy_cache = _read_patch_policy_yaml(self.policy_path)
        return self._policy_cache

    def validate_patches(self, patches: List[dict]) -> Dict[str, Any]:
        policy = self._policy() or {}
        allowed_ops = set((policy.get("allowed_ops") or []))
        safety = policy.get("safety") or {}
        require_reason = bool(safety.get("require_reason", False))
        max_patches = int(safety.get("max_patches_per_iteration", 20) or 20)
        allowed_files = (policy.get("files") or {})

        ok: List[dict] = []
        rejected: List[dict] = []

        for p in (patches or [])[:max_patches]:
            if not isinstance(p, dict):
                rejected.append({"patch": p, "reason": "patch is not an object"})
                continue
            op = str(p.get("op") or "").strip()
            file_key = str(p.get("file") or "").strip()
            path = str(p.get("path") or "").strip()
            reason = str(p.get("reason") or "").strip()

            if op not in allowed_ops:
                rejected.append({"patch": p, "reason": f"op not allowed: {op}"})
                continue
            if file_key not in allowed_files:
                rejected.append({"patch": p, "reason": f"file not allowed: {file_key}"})
                continue
            if require_reason and not reason:
                rejected.append({"patch": p, "reason": "missing reason"})
                continue

            allowed_paths = (allowed_files.get(file_key) or {}).get("allowed_paths") or []
            if not any(_path_matches_pattern(str(ap), path) for ap in allowed_paths):
                rejected.append({"patch": p, "reason": f"path not allowed: {path}"})
                continue

            if op in ("append", "replace", "merge") and ("value" not in p):
                rejected.append({"patch": p, "reason": f"missing value for op {op}"})
                continue

            ok.append(p)

        return {"accepted": ok, "rejected": rejected, "max_patches": max_patches}

    def apply_patches(self, *, ir_case_dir: str, patches: List[dict]) -> Dict[str, Any]:
        """Apply accepted patches to IR artifacts on disk."""

        l1_path, l2_path, l3_path = _load_case_ir_paths(ir_case_dir)
        gen_dir = os.path.join(ir_case_dir, "generated_query")
        bundle_path = os.path.join(gen_dir, "fragment_bundle.json")
        final_query_path = os.path.join(gen_dir, "final_query.json")

        l1 = _read_json(l1_path) if os.path.exists(l1_path) else {}
        l2 = _read_json(l2_path) if os.path.exists(l2_path) else {}
        l3 = _read_json(l3_path) if os.path.exists(l3_path) else {}
        bundle = _read_json(bundle_path) if os.path.exists(bundle_path) else {}
        finalq = _read_json(final_query_path) if os.path.exists(final_query_path) else {}

        file_map = {
            "L1_fact.json": (l1_path, l1, True),
            "L2_schema_ir.json": (l2_path, l2, True),
            "L3_logic_plan.json": (l3_path, l3, True),
            "fragment_bundle.json": (bundle_path, bundle, os.path.exists(bundle_path)),
            "final_query.json": (final_query_path, finalq, os.path.exists(final_query_path)),
        }

        applied: List[dict] = []
        errors: List[dict] = []

        for p in patches or []:
            try:
                file_key = str(p.get("file") or "").strip()
                op = str(p.get("op") or "").strip()
                path = str(p.get("path") or "").strip()
                pre = p.get("precondition")
                val = p.get("value")

                target_path, doc, exists_ok = file_map[file_key]
                if not exists_ok and file_key in ("fragment_bundle.json", "final_query.json"):
                    # Do not create new optional files.
                    raise FileNotFoundError(f"Optional artifact not found: {target_path}")

                if isinstance(pre, dict) and pre.get("path"):
                    pre_path = str(pre.get("path") or "").strip()
                    try:
                        cur_val = _get_at_pointer(doc, pre_path)
                    except Exception:
                        cur_val = None
                    if "equals" in pre and cur_val != pre.get("equals"):
                        raise ValueError("precondition failed: equals")
                    if "in" in pre:
                        allowed = pre.get("in")
                        if isinstance(allowed, list) and cur_val not in allowed:
                            raise ValueError("precondition failed: in")

                if op == "append":
                    container = _get_at_pointer(doc, path)
                    if not isinstance(container, list):
                        raise ValueError(f"append target is not a list: {path}")
                    container.append(val)
                elif op == "merge":
                    existing = _get_at_pointer(doc, path)
                    merged = _merge_value(existing, val)
                    _set_at_pointer(doc, path, merged)
                elif op == "replace":
                    _set_at_pointer(doc, path, val, replace_with_many=isinstance(val, list))
                elif op == "remove":
                    _remove_at_pointer(doc, path)
                else:
                    raise ValueError(f"unknown op: {op}")

                applied.append({"patch": p, "file_path": target_path})
            except Exception as e:
                errors.append({"patch": p, "error": f"{type(e).__name__}: {e}"})

        # Write back updated artifacts.
        for _, (p, doc, exists_ok) in file_map.items():
            if not exists_ok:
                continue
            try:
                _write_json(p, doc)
            except Exception:
                pass

        return {
            "l1": l1,
            "l2": l2,
            "l3": l3,
            "bundle": bundle,
            "final_query": finalq,
            "applied": applied,
            "errors": errors,
        }

    def derive_actions(
        self,
        *,
        failure_report: dict,
        l1: dict,
        l2: dict,
        l3: dict,
        failure_repeat_count: int = 1,
    ) -> dict:
        """Deprecated legacy hook (kept for backward compatibility).

        The policy-constrained repair flow uses DiagnoserAgent -> proposed_patches.
        """

        _ = (failure_report, l1, l2, l3, failure_repeat_count)
        return {
            "case_id": str(failure_report.get("case_id") or ""),
            "iteration": int(failure_report.get("iteration", 0) or 0),
            "primary_failure_type": failure_report.get("primary_failure_type"),
            "actions": [],
            "notes": ["derive_actions() is deprecated; use DiagnoserAgent proposed_patches."],
        }

    # NOTE: legacy heuristic update logic removed in favor of policy-constrained patches.


class RegenPlanner:
    @staticmethod
    def regen_scope_from_patched_files(files: List[str]) -> Dict[str, Any]:
        """Map modified artifact files to regeneration scope (doc section 7)."""

        files_set = set(str(f) for f in (files or []))
        scope: Dict[str, Any] = {
            "mode": "rerun_composer_only",
            "rerun_l1": False,
            "rerun_l2": False,
            "rerun_l3": False,
            "rerun_all_fragments": False,
            "rerun_steps": [],
            "rerun_composer": True,
            "reuse_existing_fragments": True,
        }

        if "L1_fact.json" in files_set:
            scope.update({"mode": "rerun_l1_l2_l3", "rerun_l1": True, "rerun_l2": True, "rerun_l3": True, "rerun_all_fragments": True, "reuse_existing_fragments": False})
        elif "L2_schema_ir.json" in files_set:
            scope.update({"mode": "rerun_l2_l3", "rerun_l2": True, "rerun_l3": True, "rerun_all_fragments": True, "reuse_existing_fragments": False})
        elif "L3_logic_plan.json" in files_set:
            scope.update({"mode": "rerun_l3", "rerun_l3": True, "rerun_all_fragments": True, "reuse_existing_fragments": False})
        elif "fragment_bundle.json" in files_set:
            scope.update({"mode": "rerun_fragments", "rerun_all_fragments": False, "reuse_existing_fragments": True})
        elif "final_query.json" in files_set:
            # The update engine has already patched `generated_query/final_query.json`.
            # Do NOT rerun the composer (it would overwrite the patched content).
            # Instead, rerun gen in "materialize" mode so we rewrite the `.ql` file
            # from the patched `final_query.json`, then proceed to validation.
            scope.update({"mode": "use_patched_final_query", "rerun_composer": False, "reuse_existing_fragments": True})

        return scope

    def build_regen_plan(
        self,
        *,
        case_id: str,
        iteration: int,
        update_actions: dict,
        primary_failure_type: str | None,
        failure_repeat_count: int,
    ) -> dict:
        """Map failure type + repeat counts to selective regeneration scope (doc section 18)."""
        ft = str(primary_failure_type or "")

        # Default: rerun composer only.
        scope: Dict[str, Any] = {
            "mode": "rerun_composer_only",
            "rerun_l1": False,
            "rerun_l2": False,
            "rerun_l3": False,
            "rerun_steps": [],
            "rerun_all_fragments": False,
            "rerun_composer": True,
        }

        if ft in ("syntax_error", "fragment_composition_conflict", "missing_import", "weak_reporting_anchor"):
            scope["mode"] = "rerun_composer_only"
        elif ft in ("unresolved_codeql_symbol", "wrong_predicate_arity", "wrong_type_constraint", "retrieval_miss", "retrieval_over_bias"):
            scope["mode"] = "rerun_fragments"
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2 and ft in ("unresolved_codeql_symbol", "wrong_type_constraint"):
                scope["mode"] = "rerun_l2_l3"
                scope["rerun_l2"] = True
                scope["rerun_l3"] = True
        elif ft in ("query_runtime_failure",):
            scope["mode"] = "rerun_fragments"
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2:
                scope["mode"] = "rerun_l3"
                scope["rerun_l3"] = True
        elif ft in ("database_analyze_failure",):
            # Environment issue: retry validate only.
            scope = {
                "mode": "retry_validate",
                "rerun_l1": False,
                "rerun_l2": False,
                "rerun_l3": False,
                "rerun_steps": [],
                "rerun_all_fragments": False,
                "rerun_composer": False,
                "retry_validate": True,
            }
        elif ft in ("empty_result_on_vulnerable",):
            # First try broadening hints/fragments; after repeat, rebuild L3.
            if failure_repeat_count >= 2:
                scope["mode"] = "rerun_l3"
                scope["rerun_l3"] = True
                scope["rerun_all_fragments"] = True
            else:
                scope["mode"] = "rerun_fragments"
                scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
        elif ft in ("target_miss_on_vulnerable",):
            # Has results but misses target: rebuild L3/anchors first; escalate to L2+L3.
            scope["mode"] = "rerun_l3"
            scope["rerun_l3"] = True
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2:
                scope["mode"] = "rerun_l2_l3"
                scope["rerun_l2"] = True
                scope["rerun_l3"] = True
        elif ft in ("false_positive_on_fixed",):
            scope["mode"] = "rerun_fragments"
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2:
                scope["mode"] = "rerun_l2_l3"
                scope["rerun_l2"] = True
                scope["rerun_l3"] = True
                scope["rerun_all_fragments"] = True
        elif ft in ("unknown_failure",):
            # Minimal fallback trigger is implemented in controller (doc section 19.2).
            scope["mode"] = "rerun_fragments"
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
        else:
            # Unknown: be conservative
            scope["mode"] = "rerun_fragments"
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True

        plan = {
            "case_id": case_id,
            "iteration": iteration,
            "primary_failure_type": ft or None,
            "failure_repeat_count": failure_repeat_count,
            "rerun_scope": scope,
            "reason": "failure_type->regen_scope mapping (section 18)",
        }
        return plan


class FeedbackLoopController:
    def __init__(
        self,
        *,
        working_dir: Optional[str],
        agent: str,
        model: str,
        ablation_mode: str,
        ir_root: str,
        generation_subdir: str,
        codeql_path: str,
        max_iters: int,
    ):
        self.working_dir = working_dir or VULNSYNTH_ROOT_DIR
        self.agent = agent
        self.model = model
        self.ablation_mode = ablation_mode
        self.ir_root = ir_root
        self.generation_subdir = generation_subdir
        self.codeql_path = codeql_path
        self.max_iters = max_iters
        self.analyzer = FailureAnalyzer()
        self.updater = UpdateEngine()
        self.planner = RegenPlanner()

    @staticmethod
    def _fallback_proposed_patches(
        *,
        cve_id: str,
        iteration: int,
        primary_failure_type: str,
        ir_case_dir: str,
        failure_report: dict,
    ) -> List[dict]:
        """Fallback patch generator when the Diagnoser Agent fails or times out.

        This keeps the repair loop progressing by writing guidance into
        generated_query/fragment_bundle.json (feedback + regen_steps), which
        the next generation pass consumes.
        """

        gen_dir = os.path.join(ir_case_dir, "generated_query")
        bundle_path = os.path.join(gen_dir, "fragment_bundle.json")
        bundle = _read_json(bundle_path) if os.path.exists(bundle_path) else {}
        existing_hist = []
        if isinstance(bundle, dict) and isinstance(bundle.get("feedback_history"), list):
            existing_hist = list(bundle.get("feedback_history") or [])

        now_utc = datetime.utcnow().isoformat() + "Z"
        entry = {
            "iteration": int(iteration),
            "timestamp_utc": now_utc,
            "primary_failure_type": str(primary_failure_type or ""),
            "summary": "fallback guidance (diagnoser unavailable)",
        }

        guidance: List[str] = []
        regen_steps: List[str] = []

        ft = str(primary_failure_type or "")
        if ft in ("syntax_error", "fragment_composition_conflict", "missing_import"):
            guidance = [
                "Fix CodeQL compilation issues caused by composition.",
                "Do not emit predicate/function signatures without bodies (no `predicate p(T x);`).",
                "Ensure helper predicate/class names are unique; never redefine common names like getMethod/getEnclosingCallable.",
                "Do not invent CodeQL APIs or higher-order predicates; verify symbols via retrieval when unsure.",
            ]
            regen_steps = []
        elif ft in ("empty_result_on_vulnerable", "target_miss_on_vulnerable"):
            guidance = [
                "Query compiles but returns 0 results on the vulnerable DB.",
                "Broaden matching: avoid overly strict constraints (exact string/fully-qualified name) unless validated.",
                "Prefer detecting the vulnerable pattern structurally (dataflow/taint) before narrowing with names.",
                "If using resource/classpath checks, allow variations (leading '/', relative names, different loaders).",
                "Re-check source/sink definitions and intermediate guards; ensure all variables are bound.",
            ]
            # Force regenerating all fragments so step-level prompts consume the guidance.
            regen_steps = ["*"]
        else:
            guidance = [
                "Repair iteration failed but diagnoser was unavailable.",
                "Simplify the query and re-check assumptions; prefer a compilable minimal query that matches the vulnerable DB.",
            ]
            regen_steps = ["*"]

        feedback_obj = {
            "case_id": cve_id,
            "iteration": int(iteration),
            "primary_failure_type": ft,
            "evidence": {
                "compile": (failure_report.get("compile") or {}),
                "execution": (failure_report.get("execution") or {}),
            },
            "guidance": guidance,
        }

        patches: List[dict] = [
            {
                "file": "fragment_bundle.json",
                "op": "replace",
                "path": "/feedback",
                "value": feedback_obj,
                "reason": "Fallback: inject actionable feedback guidance into fragment_bundle.json",
            },
            {
                "file": "fragment_bundle.json",
                "op": "replace",
                "path": "/feedback_history",
                "value": existing_hist + [entry],
                "reason": "Fallback: append a feedback_history entry to preserve iteration context",
            },
        ]
        if regen_steps:
            patches.append(
                {
                    "file": "fragment_bundle.json",
                    "op": "replace",
                    "path": "/regen_steps",
                    "value": regen_steps,
                    "reason": "Fallback: force rerun of selected steps so guidance is applied",
                }
            )
        return patches

    def _feedback_dir(self, cve_id: str) -> str:
        return os.path.join(self.working_dir, self.ir_root, cve_id, "feedback_loop")

    def _iter_dir(self, cve_id: str, iteration: int) -> str:
        return os.path.join(self._feedback_dir(cve_id), f"iter_{iteration:02d}")

    def _success(self, validation_summary: dict) -> bool:
        if not validation_summary.get("compile", {}).get("success"):
            return False
        delta = validation_summary.get("run", {}).get("delta", {})
        vuln = int(delta.get("vulnerable_results", 0) or 0)
        fixed = int(delta.get("fixed_results", 0) or 0)
        return vuln > 0 and fixed == 0

    async def run(self, cve_id: str) -> dict:
        ir_case_dir = os.path.join(self.working_dir, self.ir_root, cve_id)

        feedback_dir = self._feedback_dir(cve_id)
        _ensure_dir(feedback_dir)

        # Persistent run meta for long runs / resume after interruption.
        meta_path = os.path.join(feedback_dir, "run_meta.json")
        if os.path.exists(meta_path):
            try:
                run_meta = _read_json(meta_path)
                if not isinstance(run_meta, dict):
                    run_meta = {}
            except Exception:
                run_meta = {}
        else:
            run_meta = {}

        if not run_meta.get("started_at_utc"):
            run_meta["started_at_utc"] = datetime.utcnow().isoformat() + "Z"
        run_meta.setdefault("case_id", cve_id)
        run_meta.setdefault("ir_root", self.ir_root)
        run_meta.setdefault("elapsed_seconds_total", 0.0)

        invocation_start = time.time()

        # Persist meta early so an interrupted run still has a start marker.
        run_meta["last_updated_at_utc"] = datetime.utcnow().isoformat() + "Z"
        try:
            _write_json(meta_path, run_meta)
        except Exception:
            pass

        trace_path = os.path.join(feedback_dir, "state_trace.jsonl")
        state = "INIT"

        def _trace(event: str, to_state: str, artifacts: Optional[dict] = None) -> None:
            nonlocal state
            _append_jsonl(
                trace_path,
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "case_id": cve_id,
                    "from_state": state,
                    "event": event,
                    "to_state": to_state,
                    "artifacts": artifacts or {},
                },
            )
            state = to_state

        _trace("start_case", "PLAN_READY")

        # Resume logic: find existing iter directories and continue from next iteration.
        existing_iters: List[int] = []
        try:
            for name in os.listdir(feedback_dir):
                m = re.match(r"^iter_(\d+)$", name)
                if m:
                    existing_iters.append(int(m.group(1)))
        except Exception:
            existing_iters = []
        existing_iters = sorted(set(i for i in existing_iters if i > 0))

        start_iter = (max(existing_iters) + 1) if existing_iters else 1

        # Recover repeat counters from previous iterations (best-effort).
        last_primary_failure = None
        repeat_count = 0
        last_regen_mode: Optional[str] = None
        history: List[dict] = []
        if existing_iters:
            for it in existing_iters:
                it_dir = self._iter_dir(cve_id, it)
                fr_path = os.path.join(it_dir, "failure_report.json")
                rp_path = os.path.join(it_dir, "regen_plan.json")
                vs_path = os.path.join(it_dir, "validation_summary.json")
                try:
                    fr = _read_json(fr_path) if os.path.exists(fr_path) else {}
                    primary = fr.get("primary_failure_type")
                    if primary and primary == last_primary_failure:
                        repeat_count += 1
                    elif primary:
                        last_primary_failure = primary
                        repeat_count = 1
                except Exception:
                    pass

                try:
                    rp = _read_json(rp_path) if os.path.exists(rp_path) else {}
                    scope = rp.get("rerun_scope", {}) if isinstance(rp, dict) else {}
                    if isinstance(scope, dict) and scope.get("mode"):
                        last_regen_mode = scope.get("mode")
                except Exception:
                    pass

                try:
                    vs = _read_json(vs_path) if os.path.exists(vs_path) else {}
                    delta = (vs.get("run", {}) or {}).get("delta", {}) or {}
                    vuln_hits = int(delta.get("vulnerable_results", 0) or 0)
                    fixed_hits = int(delta.get("fixed_results", 0) or 0)
                    history.append(
                        {
                            "iteration": it,
                            "primary_failure_type": last_primary_failure,
                            "regen_mode": last_regen_mode,
                            "metrics": {"vuln_hits": vuln_hits, "fixed_hits": fixed_hits},
                        }
                    )
                except Exception:
                    pass

        # Base session id shared by multiple sessions within the loop.
        # (Coco derives role-specific sessions from this base.)
        os.environ.setdefault("COCO_SESSION_ID_BASE", f"vulnsynth-loop-{cve_id}")
        base_session = str(os.environ.get("COCO_SESSION_ID_BASE", "")).strip()
        backend_session_ids: List[str] = []
        if base_session:
            backend_session_ids = [
                f"{base_session}::plan",
                f"{base_session}::gen",
                f"{base_session}::compose",
            ]

        # Cleanup any orphaned MCP/LSP processes left by previous runs.
        _cleanup_orphan_mcp_processes()

        # Reuse agent objects/backends across the whole loop run.
        plan_agent = VulnSynthPlanAgent(
            working_dir=self.working_dir,
            agent=self.agent,
            model=self.model,
            ablation_mode=self.ablation_mode,
            codex_use_local_config=True,
        )
        gen_agent = VulnSynthGenAgent(
            working_dir=self.working_dir,
            agent=self.agent,
            model=self.model,
            ablation_mode=self.ablation_mode,
            codex_use_local_config=True,
        )
        valid_agent = VulnSynthValidAgent(working_dir=self.working_dir)

        # Diagnoser agent for policy-constrained repair.
        diagnoser_agent = VulnSynthGenAgent(
            working_dir=self.working_dir,
            agent=self.agent,
            model=self.model,
            ablation_mode=self.ablation_mode,
            codex_use_local_config=True,
        )

        # Cleanup control: best-effort cleanup for orphaned MCP/LSP processes.
        os.environ.setdefault("VULNSYNTH_CLEANUP_ORPHAN_MCP_ON_EXIT", "1")

        def _maybe_cleanup_orphans() -> None:
            if str(os.environ.get("VULNSYNTH_CLEANUP_ORPHAN_MCP_ON_EXIT", "1")).strip() in ("0", "false", "False"):
                return
            _cleanup_orphan_mcp_processes()

        def _maybe_cleanup_backend_sessions() -> None:
            if str(os.environ.get("VULNSYNTH_CLEANUP_AGENT_SESSIONS_ON_EXIT", "1")).strip() in ("0", "false", "False"):
                return
            if not backend_session_ids:
                return
            try:
                # Cleanup is backend-specific (Coco persists sessions on disk; other backends may no-op).
                plan_agent.backend.cleanup_sessions(backend_session_ids)
            except Exception:
                pass

        try:
            # Ensure plan exists.
            l1_path, l2_path, l3_path = _load_case_ir_paths(ir_case_dir)
            if not (os.path.exists(l1_path) and os.path.exists(l2_path) and os.path.exists(l3_path)):
                await plan_agent.analyze(cve_id, output_root=self.ir_root)
            _trace("plan_ok", "GEN_QUERY", {"ir_case_dir": ir_case_dir})

            # Ensure gen exists.
            gen_dir = os.path.join(ir_case_dir, self.generation_subdir)
            final_query_json_path = os.path.join(gen_dir, "final_query.json")
            if not os.path.exists(final_query_json_path):
                await gen_agent.generate(cve_id, ir_root=self.ir_root, generation_subdir=self.generation_subdir)
            _trace("gen_ok", "VALIDATE_COMPILE", {"generated_query_dir": gen_dir})

            last_summary_path = ""

            if start_iter > self.max_iters:
                _trace("budget_exhausted", "TERMINAL_FAIL", {"reason": "resume_start_iter_exceeds_max_iters"})
                final_fail = {
                    "status": "failed",
                    "iterations": self.max_iters,
                    "summary_path": last_summary_path,
                    "primary_failure_type": last_primary_failure,
                    "repeat_count": repeat_count,
                }
                run_meta["elapsed_seconds_total"] = float(run_meta.get("elapsed_seconds_total", 0.0) or 0.0) + (time.time() - invocation_start)
                run_meta["last_updated_at_utc"] = datetime.utcnow().isoformat() + "Z"
                _write_json(meta_path, run_meta)
                _write_json(os.path.join(feedback_dir, "final_failure_summary.json"), final_fail)
                final_fail["runtime_seconds_total"] = run_meta.get("elapsed_seconds_total")
                return final_fail

            for iteration in range(start_iter, self.max_iters + 1):
                iter_dir = self._iter_dir(cve_id, iteration)
                _ensure_dir(iter_dir)

                # VALIDATE_COMPILE + VALIDATE_EXEC_EVAL (combined)
                _trace("validate_start", "VALIDATE_COMPILE", {"iter_dir": iter_dir})

                valid_result = await valid_agent.validate(
                    cve_id,
                    ir_root=self.ir_root,
                    generation_subdir=self.generation_subdir,
                    codeql_path=self.codeql_path,
                    output_dir=iter_dir,
                    artifact_prefix=f"iter_{iteration:02d}",
                )
                last_summary_path = valid_result["summary_path"]
                validation_summary = _read_json(last_summary_path)
                _write_json(os.path.join(iter_dir, "validation_summary.json"), validation_summary)

                # Iteration-level housekeeping: reap orphaned MCP/LSP processes that can
                # accumulate across iterations (PPID=1 only).
                _maybe_cleanup_orphans()

                if not validation_summary.get("compile", {}).get("success"):
                    _trace("compile_fail", "ANALYZE_FAILURE", {"summary_path": last_summary_path})
                else:
                    _trace("compile_ok", "VALIDATE_EXEC_EVAL", {"summary_path": last_summary_path})

                if self._success(validation_summary):
                    _trace("eval_success", "TERMINAL_SUCCESS", {"summary_path": last_summary_path})
                    _write_json(
                        os.path.join(iter_dir, "result.json"),
                        {"status": "success", "summary_path": last_summary_path},
                    )
                    run_meta["elapsed_seconds_total"] = float(run_meta.get("elapsed_seconds_total", 0.0) or 0.0) + (
                        time.time() - invocation_start
                    )
                    run_meta["last_updated_at_utc"] = datetime.utcnow().isoformat() + "Z"
                    _write_json(meta_path, run_meta)
                    return {
                        "status": "success",
                        "iterations": iteration,
                        "summary_path": last_summary_path,
                        "runtime_seconds_total": run_meta.get("elapsed_seconds_total"),
                    }

                # Failure path: analyze -> diagnose -> policy-constrained repair -> regen plan
                _trace("eval_fail", "ANALYZE_FAILURE", {"summary_path": last_summary_path})
                l1, l2, l3 = _load_case_ir(ir_case_dir)
                failure_report = self.analyzer.analyze(
                    case_id=cve_id, iteration=iteration, validation_summary=validation_summary
                )
                _write_json(os.path.join(iter_dir, "failure_report.json"), failure_report)

                primary = failure_report.get("primary_failure_type")

                # Regen fallback trigger T2: soft reset (from L1) didn't fix -> full reset.
                force_full_reset = bool(last_regen_mode == "fallback_replan_from_l1")

                if primary and primary == last_primary_failure:
                    repeat_count += 1
                else:
                    last_primary_failure = primary
                    repeat_count = 1
                _trace(
                    "analyze_ok",
                    "DIAGNOSE_FAILURE",
                    {"primary_failure_type": primary, "repeat_count": repeat_count},
                )

                # Diagnoser Agent produces structured diagnosis + proposed_patches.
                diagnosis_report: Dict[str, Any]
                try:
                    cve_dir, repo_path, diff_path = discover_cve_paths(cve_id)
                    task = VulnSynthTask(
                        cve_id=cve_id,
                        cve_dir=cve_dir,
                        repo_path=repo_path,
                        diff_path=diff_path,
                        fix_commit_diff=_preprocess_diff(_read_text(diff_path)),
                        cve_description=_maybe_load_cve_description(cve_id),
                    )
                    policy_path = os.path.join(VULNSYNTH_ROOT_DIR, "patch_policy.yaml")
                    # Keep the diagnoser prompt compact to avoid OS ARG_MAX limits.
                    # The diagnoser should read full artifacts from disk.
                    compile_tail = _tail(str((validation_summary.get("compile") or {}).get("stderr_tail") or ""), max_lines=20)
                    failure_tail = _tail(str(failure_report.get("compile", {}).get("stderr_summary") or ""), max_lines=20)
                    validation_snippet = json.dumps(
                        {
                            "compile_success": bool((validation_summary.get("compile") or {}).get("success")),
                            "compile_stderr_tail": compile_tail,
                            "query_path": str(validation_summary.get("query_path") or ""),
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                    failure_snippet = json.dumps(
                        {
                            "primary_failure_type": failure_report.get("primary_failure_type"),
                            "compile_stderr_summary_tail": failure_tail,
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                    prompt = vulnsynth_prompts.build_diagnosis_prompt(
                        task,
                        iteration=iteration,
                        validation_summary_path=os.path.join(iter_dir, "validation_summary.json"),
                        failure_report_path=os.path.join(iter_dir, "failure_report.json"),
                        patch_policy_path=policy_path,
                        validation_summary_snippet=validation_snippet,
                        failure_report_snippet=failure_snippet,
                    )
                    diag_dir = os.path.join(iter_dir, "diagnosis")
                    _ensure_dir(diag_dir)
                    # Prevent a stuck diagnoser from blocking the feedback loop.
                    try:
                        diagnosis_report = await asyncio.wait_for(
                            diagnoser_agent._run_stage(
                                "diagnose",
                                prompt,
                                diag_dir,
                            ),
                            timeout=float(os.environ.get("VULNSYNTH_DIAGNOSE_TIMEOUT_SEC", "240") or 240.0),
                        )
                    except asyncio.TimeoutError:
                        diagnosis_report = {
                            "case_id": cve_id,
                            "iteration": iteration,
                            "primary_failure_type": primary or "unknown_failure",
                            "confidence": 0.2,
                            "evidence": {"error": "diagnoser_timeout"},
                            "suspected_layers": ["diagnoser"],
                            "proposed_patches": self._fallback_proposed_patches(
                                cve_id=cve_id,
                                iteration=iteration,
                                primary_failure_type=str(primary or "unknown_failure"),
                                ir_case_dir=ir_case_dir,
                                failure_report=failure_report,
                            ),
                        }
                    if not isinstance(diagnosis_report, dict):
                        diagnosis_report = {"raw": diagnosis_report}
                except Exception as e:
                    diagnosis_report = {
                        "case_id": cve_id,
                        "iteration": iteration,
                        "primary_failure_type": primary or "unknown_failure",
                        "confidence": 0.2,
                        "evidence": {"error": f"diagnoser_failed: {type(e).__name__}: {e}"},
                        "suspected_layers": ["diagnoser"],
                        "proposed_patches": self._fallback_proposed_patches(
                            cve_id=cve_id,
                            iteration=iteration,
                            primary_failure_type=str(primary or "unknown_failure"),
                            ir_case_dir=ir_case_dir,
                            failure_report=failure_report,
                        ),
                    }

                _write_json(os.path.join(iter_dir, "diagnosis_report.json"), diagnosis_report)
                _trace("diagnose_ok", "APPLY_UPDATE", {"proposed_patches": len(diagnosis_report.get("proposed_patches") or [])})

                proposed = diagnosis_report.get("proposed_patches")
                proposed_list = proposed if isinstance(proposed, list) else []
                policy_check = self.updater.validate_patches(proposed_list)
                accepted = policy_check.get("accepted") or []
                rejected = policy_check.get("rejected") or []

                _write_json(
                    os.path.join(iter_dir, "update_actions.json"),
                    {
                        "case_id": cve_id,
                        "iteration": iteration,
                        "patches": accepted,
                        "rejected": rejected,
                    },
                )

                applied_result = self.updater.apply_patches(ir_case_dir=ir_case_dir, patches=accepted)
                _write_json(os.path.join(iter_dir, "updated_l1.json"), applied_result.get("l1") or {})
                _write_json(os.path.join(iter_dir, "updated_l2.json"), applied_result.get("l2") or {})
                _write_json(os.path.join(iter_dir, "updated_l3.json"), applied_result.get("l3") or {})

                # Use actually-applied patches when deciding regen scope.
                applied_patches = applied_result.get("applied") or []
                patched_files = []
                for ap in applied_patches:
                    if not isinstance(ap, dict):
                        continue
                    p = ap.get("patch")
                    if isinstance(p, dict):
                        patched_files.append(str(p.get("file") or "").strip())
                regen_scope = RegenPlanner.regen_scope_from_patched_files(patched_files)

                # If the diagnoser patched fragment_bundle.json:/regen_steps, honor it by mapping
                # to the actual generation parameter rerun_steps.
                bundle = applied_result.get("bundle")
                if isinstance(bundle, dict):
                    regen_steps = bundle.get("regen_steps")
                    if isinstance(regen_steps, list) and all(isinstance(s, str) and s.strip() for s in regen_steps):
                        regen_scope["rerun_steps"] = [str(s).strip() for s in regen_steps]
                        regen_scope["mode"] = "rerun_fragments"
                        regen_scope["rerun_all_fragments"] = False
                        regen_scope["rerun_composer"] = True
                        regen_scope["reuse_existing_fragments"] = True
                regen_plan = {
                    "case_id": cve_id,
                    "iteration": iteration,
                    "primary_failure_type": primary,
                    "failure_repeat_count": repeat_count,
                    "rerun_scope": regen_scope,
                    "reason": "policy-constrained repair -> regen scope mapping",
                }

                # Fallback trigger T1: 2 consecutive unknown failures -> fallback_replan_from_l1.
                if primary == "unknown_failure" and repeat_count >= 2:
                    regen_plan["rerun_scope"] = {"mode": "fallback_replan_from_l1"}
                    regen_plan["reason"] = "T1: consecutive unknown_failure >= 2"

                # Fallback trigger T2: after fallback_replan_from_l1, still failing -> full reset.
                if force_full_reset:
                    regen_plan["rerun_scope"] = {"mode": "fallback_full_replan_from_inputs"}
                    regen_plan["reason"] = "T2: soft reset from L1 did not converge"

                # Fallback trigger T3: local patch 3 rounds without metric improvement -> fallback from L1.
                # Use metrics from validation_summary: vuln_hits should increase OR fixed_hits should decrease.
                delta = validation_summary.get("run", {}).get("delta", {})
                vuln_hits = int(delta.get("vulnerable_results", 0) or 0)
                fixed_hits = int(delta.get("fixed_results", 0) or 0)
                proposed_mode = (regen_plan.get("rerun_scope", {}) or {}).get("mode")
                history.append(
                    {
                        "iteration": iteration,
                        "primary_failure_type": primary,
                        "regen_mode": proposed_mode,
                        "metrics": {"vuln_hits": vuln_hits, "fixed_hits": fixed_hits},
                    }
                )
                if len(history) >= 3:
                    window = history[-3:]
                    local_modes = {"rerun_composer_only", "rerun_fragments", "rerun_l3"}
                    if all((e.get("regen_mode") in local_modes) for e in window):
                        base = window[0].get("metrics", {})
                        improved = False
                        prev_v = int(base.get("vuln_hits", 0) or 0)
                        prev_f = int(base.get("fixed_hits", 0) or 0)
                        for e in window[1:]:
                            m = e.get("metrics", {})
                            v = int(m.get("vuln_hits", 0) or 0)
                            f = int(m.get("fixed_hits", 0) or 0)
                            if v > prev_v or f < prev_f:
                                improved = True
                            prev_v, prev_f = v, f
                        if not improved and not force_full_reset and not (
                            primary == "unknown_failure" and repeat_count >= 2
                        ):
                            regen_plan["rerun_scope"] = {"mode": "fallback_replan_from_l1"}
                            regen_plan["reason"] = "T3: local patch >= 3 without improvement"
                _write_json(os.path.join(iter_dir, "regen_plan.json"), regen_plan)
                _trace("update_ok", "PLAN_REGEN_SCOPE", {"regen_plan": regen_plan.get("rerun_scope", {})})

                # Stop if we have reached the iteration limit.
                if iteration >= self.max_iters:
                    break

                scope = regen_plan.get("rerun_scope", {})
                # Selective regeneration per scope.
                if scope.get("retry_validate"):
                    _trace("retry_validate", "VALIDATE_COMPILE")
                    continue

                # Fallback modes (doc section 19): reset parts of lineage.
                mode = scope.get("mode") if isinstance(scope, dict) else None
                if mode in ("fallback_replan_from_l1", "fallback_full_replan_from_inputs"):
                    _trace("fallback_mode", "PLAN_READY", {"mode": mode})

                    # Drop derived artifacts per design doc: keep feedback_loop + trace.
                    l1_path, l2_path, l3_path = _load_case_ir_paths(ir_case_dir)
                    gen_dir = os.path.join(ir_case_dir, self.generation_subdir)

                    # Preserve loop-control guidance that is intentionally carried in
                    # `fragment_bundle.json` across iterations. Fallback resets delete
                    # `generated_query/`, so without this we silently drop diagnoser
                    # guidance (`/feedback`, `/feedback_history`, `/regen_steps`).
                    preserved_bundle_fields: Dict[str, Any] = {}
                    try:
                        fb_path = os.path.join(gen_dir, "fragment_bundle.json")
                        if os.path.exists(fb_path):
                            fb_obj = _read_json(fb_path)
                            if isinstance(fb_obj, dict):
                                for k in ("feedback", "feedback_history", "regen_steps"):
                                    if k in fb_obj:
                                        preserved_bundle_fields[k] = fb_obj.get(k)
                    except Exception:
                        preserved_bundle_fields = {}
                    try:
                        if os.path.isdir(gen_dir):
                            shutil.rmtree(gen_dir, ignore_errors=True)
                    except Exception:
                        pass

                    for p in (l2_path, l3_path):
                        try:
                            if os.path.exists(p):
                                os.remove(p)
                        except Exception:
                            pass
                    if mode == "fallback_full_replan_from_inputs":
                        try:
                            if os.path.exists(l1_path):
                                os.remove(l1_path)
                        except Exception:
                            pass
                    await plan_agent.analyze(cve_id, output_root=self.ir_root)

                    # Seed the new generation directory with the preserved guidance so
                    # fragment generation prompts can see it even after a fallback reset.
                    if preserved_bundle_fields:
                        try:
                            os.makedirs(gen_dir, exist_ok=True)
                            seed = {"case_id": cve_id, "fragments": []}
                            seed.update(preserved_bundle_fields)
                            _write_json(os.path.join(gen_dir, "fragment_bundle.json"), seed)
                        except Exception:
                            pass
                    _trace("rerun_gen", "GEN_QUERY", {"mode": mode})
                    await gen_agent.generate(
                        cve_id,
                        ir_root=self.ir_root,
                        generation_subdir=self.generation_subdir,
                        rerun_steps=["*"],
                        rerun_composer=True,
                        # Still reruns everything (rerun_steps=["*"]), but allows loading
                        # the seeded bundle so loop feedback is injected into step prompts.
                        reuse_existing_fragments=True,
                    )
                    _trace("gen_ok", "VALIDATE_COMPILE")
                    last_regen_mode = mode
                    continue

                # PLAN regeneration (L1/L2/L3)
                if scope.get("rerun_l1") or scope.get("rerun_l2") or scope.get("rerun_l3"):
                    _trace("rerun_plan", "PLAN_READY", scope)
                    await plan_agent.analyze_partial(
                        cve_id,
                        output_root=self.ir_root,
                        rerun_l1=bool(scope.get("rerun_l1")),
                        rerun_l2=bool(scope.get("rerun_l2")),
                        rerun_l3=bool(scope.get("rerun_l3")),
                    )
                    _trace("plan_ok", "GEN_QUERY")
                _trace("rerun_gen", "GEN_QUERY", scope)
                await gen_agent.generate(
                    cve_id,
                    ir_root=self.ir_root,
                    generation_subdir=self.generation_subdir,
                    rerun_steps=scope.get("rerun_steps")
                    if scope.get("rerun_steps")
                    else (["*"] if scope.get("rerun_all_fragments") else []),
                    rerun_composer=bool(scope.get("rerun_composer", True)),
                    reuse_existing_fragments=not bool(scope.get("rerun_all_fragments")),
                )
                _trace("gen_ok", "VALIDATE_COMPILE")
                last_regen_mode = scope.get("mode") if isinstance(scope, dict) else None

            _trace("budget_exhausted", "TERMINAL_FAIL", {"summary_path": last_summary_path})
            final_fail = {
                "status": "failed",
                "iterations": self.max_iters,
                "summary_path": last_summary_path,
                "primary_failure_type": last_primary_failure,
                "repeat_count": repeat_count,
            }
            run_meta["elapsed_seconds_total"] = float(run_meta.get("elapsed_seconds_total", 0.0) or 0.0) + (time.time() - invocation_start)
            run_meta["last_updated_at_utc"] = datetime.utcnow().isoformat() + "Z"
            _write_json(meta_path, run_meta)
            _write_json(os.path.join(feedback_dir, "final_failure_summary.json"), final_fail)
            final_fail["runtime_seconds_total"] = run_meta.get("elapsed_seconds_total")
            return final_fail
        finally:
            # Always cleanup across success/failure/interrupt.
            _maybe_cleanup_orphans()
            _maybe_cleanup_backend_sessions()


async def main() -> None:
    parser = argparse.ArgumentParser(description="VulnSynth plan/gen agent")
    parser.add_argument("--mode", default="plan", choices=["plan", "gen", "valid", "loop", "all"])
    parser.add_argument("--cve-id", required=True, help="CVE identifier")
    parser.add_argument("--agent", default="codex", choices=["codex", "coco"], help="Agent backend to use")
    parser.add_argument("--output-root", default="src/IR", help="Relative output root directory")
    parser.add_argument("--ir-root", default=None, help="IR root for gen mode; defaults to --output-root")
    parser.add_argument("--generation-subdir", default="generated_query", help="Subdirectory for gen outputs under the IR case directory")
    parser.add_argument("--model", default="gpt-5", help="Codex model id")
    parser.add_argument("--ablation-mode", default="full", choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"])
    parser.add_argument("--working-dir", default=None, help="Workspace root; defaults to repository root")
    parser.add_argument("--compile-query", action="store_true", help="Compile-check the generated CodeQL query")
    parser.add_argument(
        "--codeql-path",
        default=os.environ.get("CODEQL_PATH", "") or shutil.which("codeql") or "",
        help="Path to the CodeQL CLI executable",
    )
    parser.add_argument("--max-iters", type=int, default=3, help="Max iterations for feedback loop mode")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    ir_root = args.ir_root or args.output_root

    if args.mode in ("plan", "all"):
        plan_agent = VulnSynthPlanAgent(
            working_dir=args.working_dir,
            agent=args.agent,
            model=args.model,
            ablation_mode=args.ablation_mode,
            codex_use_local_config=True,
        )
        plan_result = await plan_agent.analyze(args.cve_id, output_root=args.output_root)
        print("VulnSynth plan generation completed")
        print(f"Output directory: {plan_result['output_dir']}")
        print(f"L1: {plan_result['l1_path']}")
        print(f"L2: {plan_result['l2_path']}")
        print(f"L3: {plan_result['l3_path']}")

    if args.mode in ("gen", "all"):
        gen_agent = VulnSynthGenAgent(
            working_dir=args.working_dir,
            agent=args.agent,
            model=args.model,
            ablation_mode=args.ablation_mode,
            codex_use_local_config=True,
        )
        gen_result = await gen_agent.generate(
            args.cve_id,
            ir_root=ir_root,
            generation_subdir=args.generation_subdir,
        )
        print("VulnSynth query generation completed")
        print(f"Generation directory: {gen_result['output_dir']}")
        print(f"Fragments: {gen_result['fragments_dir']}")
        print(f"Fragment bundle: {gen_result['fragment_bundle_path']}")
        print(f"Final query JSON: {gen_result['final_query_json_path']}")
        print(f"Final query: {gen_result['final_query_path']}")
        if args.compile_query:
            compile_result = compile_codeql_query(
                gen_result["final_query_path"],
                _infer_language_from_ir(
                    _read_json(os.path.join(ir_root, args.cve_id, "cve_facts.json")),
                    discover_cve_paths(args.cve_id)[1],
                ),
                args.codeql_path,
                gen_result["output_dir"],
            )
            print("VulnSynth compile check completed")
            print(f"Compile success: {compile_result['success']}")
            print(f"Compile result: {os.path.join(gen_result['output_dir'], 'compile_result.json')}")

    if args.mode == "valid":
        valid_agent = VulnSynthValidAgent(working_dir=args.working_dir)
        valid_result = await valid_agent.validate(
            args.cve_id,
            ir_root=ir_root,
            generation_subdir=args.generation_subdir,
            codeql_path=args.codeql_path,
        )
        print("VulnSynth query validation completed")
        print(f"Query: {valid_result['query_path']}")
        print(f"Generated query dir: {valid_result['generated_query_dir']}")
        print(f"Validation summary: {valid_result['summary_path']}")

    if args.mode == "loop":
        controller = FeedbackLoopController(
            working_dir=args.working_dir,
            agent=args.agent,
            model=args.model,
            ablation_mode=args.ablation_mode,
            ir_root=ir_root,
            generation_subdir=args.generation_subdir,
            codeql_path=args.codeql_path,
            max_iters=args.max_iters,
        )
        result = await controller.run(args.cve_id)
        print("VulnSynth feedback loop completed")
        print(f"Status: {result['status']}")
        print(f"Iterations: {result['iterations']}")
        print(f"Last validation summary: {result.get('summary_path', '')}")
        if result.get("runtime_seconds_total") is not None:
            print(f"Runtime seconds (total): {result.get('runtime_seconds_total')}")


if __name__ == "__main__":
    asyncio.run(main())
