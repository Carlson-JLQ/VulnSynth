#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import csv
from dataclasses import asdict
import json
import logging
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

os.environ["ANONYMIZED_TELEMETRY"] = "false"

try:
    from .agent_backends import create_backend
    from .agent_backends import vulnsynth_prompts
    from .query_subagents_evaluation import compile_query_once, run_query_with_evaluation_results
except ImportError:
    from agent_backends import create_backend
    from agent_backends import vulnsynth_prompts
    from query_subagents_evaluation import compile_query_once, run_query_with_evaluation_results

try:
    from .config import CODEQL_PATH, CVES_PATH, NVD_CACHE, VULNSYNTH_ROOT_DIR
except Exception:
    try:
        from config import CODEQL_PATH, CVES_PATH, NVD_CACHE, VULNSYNTH_ROOT_DIR
    except Exception:
        VULNSYNTH_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        CVES_PATH = os.path.join(VULNSYNTH_ROOT_DIR, "cves")
        NVD_CACHE = "nist_cve_cache"
        CODEQL_PATH = os.environ.get("CODEQL_PATH", "")


LOGGER = logging.getLogger("vulnsynth")

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


@dataclass
class StageSessionTurn:
    step_name: str
    prompt_path: str
    raw_output_path: str
    parsed_output_path: Optional[str]
    parsed_output: Optional[Dict[str, Any]]
    assistant_text_path: str
    assistant_text: str


class StageSession:
    """
    Stage-scoped session wrapper.

    Prefer native Codex thread resumption when available, and fall back
    to virtual prompt replay when a native thread has not been established.
    """

    def __init__(self, session_name: str, session_dir: str):
        self.session_name = session_name
        self.session_dir = session_dir
        self.turns: list[StageSessionTurn] = []
        self.native_thread_id: Optional[str] = None
        os.makedirs(self.session_dir, exist_ok=True)

    def build_prompt(self, task_prompt: str) -> str:
        if self.native_thread_id:
            return task_prompt
        if not self.turns:
            return task_prompt

        lines = [
            f"# Session Context: {self.session_name}",
            "You are continuing the same stage-scoped workflow.",
            "Use the previous structured outputs as authoritative context.",
            "Do not repeat prior work unless necessary for consistency.",
            "",
            "## Prior Turns",
        ]

        for index, turn in enumerate(self.turns, start=1):
            lines.append(f"### Turn {index}: {turn.step_name}")
            if turn.parsed_output is not None:
                parsed_json = json.dumps(turn.parsed_output, indent=2, ensure_ascii=False)
                lines.append("Parsed structured output:")
                lines.append("```json")
                lines.append(parsed_json)
                lines.append("```")
            else:
                trimmed = turn.assistant_text.strip()
                if len(trimmed) > 4000:
                    trimmed = trimmed[:4000] + "\n...[truncated session history]..."
                lines.append("Assistant output summary:")
                lines.append("```text")
                lines.append(trimmed)
                lines.append("```")
            lines.append("")

        lines.extend(
            [
                "## Current Turn",
                task_prompt,
            ]
        )
        return "\n".join(lines)

    def add_turn(
        self,
        step_name: str,
        prompt_path: str,
        raw_output_path: str,
        parsed_output_path: Optional[str],
        parsed_output: Optional[Dict[str, Any]],
        assistant_text_path: str,
        assistant_text: str,
        native_thread_id: Optional[str] = None,
    ) -> None:
        if native_thread_id:
            self.native_thread_id = native_thread_id
        self.turns.append(
            StageSessionTurn(
                step_name=step_name,
                prompt_path=prompt_path,
                raw_output_path=raw_output_path,
                parsed_output_path=parsed_output_path,
                parsed_output=parsed_output,
                assistant_text_path=assistant_text_path,
                assistant_text=assistant_text,
            )
        )
        self._write_manifest()

    def _write_manifest(self) -> None:
        manifest = {
            "session_name": self.session_name,
            "native_thread_id": self.native_thread_id,
            "turn_count": len(self.turns),
            "turns": [
                {
                    "step_name": turn.step_name,
                    "prompt_path": turn.prompt_path,
                    "raw_output_path": turn.raw_output_path,
                    "parsed_output_path": turn.parsed_output_path,
                    "assistant_text_path": turn.assistant_text_path,
                }
                for turn in self.turns
            ],
        }
        _write_json(os.path.join(self.session_dir, "session_manifest.json"), manifest)


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
    _write_json(os.path.join(output_dir, "compile_result.json"), result)
    _write_text(os.path.join(output_dir, "compile_stdout.log"), proc.stdout)
    _write_text(os.path.join(output_dir, "compile_stderr.log"), proc.stderr)
    return result


def _ensure_query_qlpack(output_dir: str, language: str) -> str:
    dependency_map = {
        "java": "codeql/java-all",
        "cpp": "codeql/cpp-all",
    }
    dependency = dependency_map.get(language)
    if dependency is None:
        raise ValueError(f"Unsupported language for qlpack generation: {language}")

    qlpack_path = os.path.join(output_dir, "qlpack.yml")
    _write_yaml_like_text(
        qlpack_path,
        (
            "name: vulnsynth/generated\n"
            "version: 0.0.1\n"
            "dependencies:\n"
            f"  {dependency}: \"*\"\n"
        ),
    )
    return qlpack_path


def _prepare_query_workspace(
    *,
    output_dir: str,
    source_query_path: str,
    language: str,
) -> Dict[str, str]:
    workspace_dir = tempfile.mkdtemp(prefix="vulnsynth_query_workspace_", dir=output_dir)
    workspace_query_path = os.path.join(workspace_dir, os.path.basename(source_query_path))
    _write_text(workspace_query_path, _read_text(source_query_path))
    workspace_qlpack_path = _ensure_query_qlpack(workspace_dir, language)
    manifest = {
        "workspace_dir": workspace_dir,
        "source_query_path": source_query_path,
        "workspace_query_path": workspace_query_path,
        "workspace_qlpack_path": workspace_qlpack_path,
    }
    _write_json(os.path.join(workspace_dir, "workspace_manifest.json"), manifest)
    return manifest


def _discover_codeql_databases(cve_dir: str, cve_id: str, language: str) -> tuple[str, str]:
    db_suffix_map = {
        "java": "db-java",
        "cpp": "db-cpp",
    }
    db_dir_name = db_suffix_map.get(language)
    if db_dir_name is None:
        raise ValueError(f"Unsupported language for database discovery: {language}")

    vuln_db = os.path.join(cve_dir, f"{cve_id}-vul", db_dir_name)
    fixed_db = os.path.join(cve_dir, f"{cve_id}-fix", db_dir_name)

    if os.path.isdir(vuln_db) and os.path.isdir(fixed_db):
        return vuln_db, fixed_db

    matches: dict[str, Optional[str]] = {"vul": None, "fix": None}
    for root, dirs, _files in os.walk(cve_dir):
        for dirname in dirs:
            if dirname != db_dir_name:
                continue
            full_path = os.path.join(root, dirname)
            lower = full_path.lower()
            if matches["vul"] is None and "-vul" in lower:
                matches["vul"] = full_path
            elif matches["fix"] is None and "-fix" in lower:
                matches["fix"] = full_path
        if all(matches.values()):
            break

    if matches["vul"] and matches["fix"]:
        return str(matches["vul"]), str(matches["fix"])

    raise FileNotFoundError(
        f"Could not discover vulnerable/fixed CodeQL databases for {cve_id} in {cve_dir}"
    )


async def _compile_and_run_generated_query(
    *,
    cve_id: str,
    cve_dir: str,
    query_path: str,
    language: str,
    output_dir: str,
    logger: logging.Logger,
) -> Dict[str, Any]:
    workspace = _prepare_query_workspace(
        output_dir=output_dir,
        source_query_path=query_path,
        language=language,
    )
    qlpack_path = workspace["workspace_qlpack_path"]
    workspace_dir = workspace["workspace_dir"]
    workspace_query_path = workspace["workspace_query_path"]
    execution_result_path = os.path.join(output_dir, "execution_result.json")
    try:
        compilation_summary = await compile_query_once(workspace_query_path, logger)
        compilation_success = "COMPILATION SUCCESS" in compilation_summary
        compilation_summary_path = os.path.join(output_dir, "compilation_summary.txt")
        _write_text(compilation_summary_path, compilation_summary.rstrip() + "\n")

        result: Dict[str, Any] = {
            "qlpack_path": qlpack_path,
            "query_path": query_path,
            "workspace_dir": workspace_dir,
            "workspace_query_path": workspace_query_path,
            "language": language,
            "compilation_success": compilation_success,
            "compilation_summary": compilation_summary,
            "compilation_summary_path": compilation_summary_path,
        }

        if not compilation_success:
            result["execution_skipped"] = True
            result["execution_success"] = False
            _write_json(execution_result_path, result)
            result["execution_result_path"] = execution_result_path
            return result

        vuln_db_path, fixed_db_path = _discover_codeql_databases(cve_dir, cve_id, language)
        execution_summary, vuln_eval, fixed_eval, execution_success = await run_query_with_evaluation_results(
            query_path=workspace_query_path,
            vuln_db_path=vuln_db_path,
            fixed_db_path=fixed_db_path,
            cve_id=cve_id,
            iteration_number=1,
            output_dir=output_dir,
            logger=logger,
        )
        execution_summary_path = os.path.join(output_dir, "execution_summary.txt")
        _write_text(execution_summary_path, execution_summary.rstrip() + "\n")

        result.update(
            {
                "execution_skipped": False,
                "execution_success": execution_success,
                "execution_summary": execution_summary,
                "execution_summary_path": execution_summary_path,
                "vuln_db_path": vuln_db_path,
                "fixed_db_path": fixed_db_path,
                "vuln_eval": asdict(vuln_eval),
                "fixed_eval": asdict(fixed_eval),
            }
        )
        _write_json(execution_result_path, result)
        result["execution_result_path"] = execution_result_path
        return result
    except Exception as exc:
        failure = {
            "qlpack_path": qlpack_path,
            "query_path": query_path,
            "workspace_dir": workspace_dir,
            "workspace_query_path": workspace_query_path,
            "language": language,
            "compilation_success": False,
            "execution_skipped": False,
            "execution_success": False,
            "error": str(exc),
        }
        _write_json(execution_result_path, failure)
        failure["execution_result_path"] = execution_result_path
        return failure


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
    hints = step.get("retrieval_hints", {})
    keywords = hints.get("keywords", [])
    classes = hints.get("candidate_classes", [])
    predicates = hints.get("candidate_predicates", [])
    patterns = hints.get("reference_query_patterns", [])
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

    return {
        "step_id": step.get("step_id"),
        "language": language,
        "retrieval_targets": targets,
        "global_collections": registry["global"],
        "language_collections": registry["language_specific"],
        "query_views": query_views,
        "collection_query_map": collection_queries,
    }


class VulnSynthPlanAgent:
    def __init__(
        self,
        working_dir: Optional[str] = None,
        model: str = "gpt-5",
        ablation_mode: str = "full",
        codex_use_local_config: bool = True,
    ):
        self.working_dir = working_dir or VULNSYNTH_ROOT_DIR
        self.logger = LOGGER
        self.backend = create_backend(
            "codex",
            model,
            self.logger,
            ablation_mode=ablation_mode,
            use_local_config=codex_use_local_config,
        )

    async def _run_stage(
        self,
        stage_name: str,
        prompt: str,
        output_dir: str,
        session: Optional[StageSession] = None,
    ) -> Dict[str, Any]:
        prompt_path = os.path.join(output_dir, f"{stage_name}_prompt.md")
        effective_prompt = session.build_prompt(prompt) if session else prompt
        _write_text(prompt_path, effective_prompt)
        native_handle = None
        if session and getattr(self.backend, "supports_native_sessions", lambda: False)():
            if session.native_thread_id:
                native_handle = self.backend.create_native_session_handle(
                    session.native_thread_id,
                    stage_name,
                )

        result = await self.backend.execute_prompt(
            prompt=effective_prompt,
            env=os.environ.copy(),
            cwd=self.working_dir,
            phase_name=stage_name,
            native_session=native_handle,
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
        assistant_path = os.path.join(output_dir, f"{stage_name}_assistant.txt")
        _write_text(assistant_path, text_output)
        parsed = _extract_json_object(text_output)
        parsed_path = os.path.join(output_dir, f"{stage_name}_parsed.json")
        _write_json(parsed_path, parsed)
        if session:
            session.add_turn(
                step_name=stage_name,
                prompt_path=prompt_path,
                raw_output_path=stdout_path,
                parsed_output_path=parsed_path,
                parsed_output=parsed,
                assistant_text_path=assistant_path,
                assistant_text=text_output,
                native_thread_id=result.get("thread_id"),
            )
        return parsed

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

        self.logger.info(f"Using repository root: {repo_path}")
        self.logger.info(f"Writing IR outputs to: {output_dir}")

        try:
            self.logger.info("Pre-cleaning MCP/LSP processes before plan stage")
            await self.backend.cleanup()
            self.backend.setup_workspace(output_dir, task)
            plan_session = StageSession("plan", os.path.join(output_dir, "sessions", "plan"))

            metadata = {
                "cve_id": cve_id,
                "repo_path": repo_path,
                "diff_path": diff_path,
                "output_dir": output_dir,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "backend": "codex",
                "model": self.backend.model,
                "ablation_mode": self.backend.ablation_mode,
                "session_architecture": {
                    "plan": "native Codex session when available, with virtual replay fallback",
                },
            }
            _write_json(os.path.join(output_dir, "metadata.json"), metadata)

            self.logger.info("Stage 1/3: generating L1 facts")
            l1 = await self._run_stage(
                "stage1_l1",
                vulnsynth_prompts.build_l1_prompt(task),
                output_dir,
                session=plan_session,
            )
            _write_json(os.path.join(output_dir, "cve_facts.json"), l1)

            self.logger.info("Stage 2/3: generating L2 schema IR")
            l2 = await self._run_stage(
                "stage2_l2",
                vulnsynth_prompts.build_l2_prompt(task, json.dumps(l1, indent=2, ensure_ascii=False)),
                output_dir,
                session=plan_session,
            )
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
                session=plan_session,
            )
            _write_json(os.path.join(output_dir, "codeql_logic_steps.json"), l3)

            return {
                "output_dir": output_dir,
                "l1_path": os.path.join(output_dir, "cve_facts.json"),
                "l2_path": os.path.join(output_dir, "codeql_schema_ir.json"),
                "l3_path": os.path.join(output_dir, "codeql_logic_steps.json"),
            }
        finally:
            self.logger.info("Cleaning up MCP/LSP processes after plan stage")
            await self.backend.cleanup()


class VulnSynthGenAgent:
    def __init__(
        self,
        working_dir: Optional[str] = None,
        model: str = "gpt-5",
        ablation_mode: str = "full",
        codex_use_local_config: bool = True,
    ):
        self.working_dir = working_dir or VULNSYNTH_ROOT_DIR
        self.logger = LOGGER
        self.backend = create_backend(
            "codex",
            model,
            self.logger,
            ablation_mode=ablation_mode,
            use_local_config=codex_use_local_config,
        )

    async def _run_stage(
        self,
        stage_name: str,
        prompt: str,
        output_dir: str,
        session: Optional[StageSession] = None,
    ) -> Dict[str, Any]:
        prompt_path = os.path.join(output_dir, f"{stage_name}_prompt.md")
        effective_prompt = session.build_prompt(prompt) if session else prompt
        _write_text(prompt_path, effective_prompt)
        native_handle = None
        if session and getattr(self.backend, "supports_native_sessions", lambda: False)():
            if session.native_thread_id:
                native_handle = self.backend.create_native_session_handle(
                    session.native_thread_id,
                    stage_name,
                )

        result = await self.backend.execute_prompt(
            prompt=effective_prompt,
            env=os.environ.copy(),
            cwd=self.working_dir,
            phase_name=stage_name,
            native_session=native_handle,
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
        assistant_path = os.path.join(output_dir, f"{stage_name}_assistant.txt")
        _write_text(assistant_path, text_output)
        parsed = _extract_json_object(text_output)
        parsed_path = os.path.join(output_dir, f"{stage_name}_parsed.json")
        _write_json(parsed_path, parsed)
        if session:
            session.add_turn(
                step_name=stage_name,
                prompt_path=prompt_path,
                raw_output_path=stdout_path,
                parsed_output_path=parsed_path,
                parsed_output=parsed,
                assistant_text_path=assistant_path,
                assistant_text=text_output,
                native_thread_id=result.get("thread_id"),
            )
        return parsed

    async def generate(
        self,
        cve_id: str,
        ir_root: str = "src/IR",
        generation_subdir: str = "generated_query",
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
        output_dir = os.path.join(ir_case_dir, generation_subdir)
        fragments_dir = os.path.join(output_dir, "fragments")
        os.makedirs(fragments_dir, exist_ok=True)
        try:
            self.logger.info("Pre-cleaning MCP/LSP processes before gen stage")
            await self.backend.cleanup()
            self.backend.setup_workspace(output_dir, task)
            fragments_session = StageSession(
                "gen-fragments",
                os.path.join(output_dir, "sessions", "gen_fragments"),
            )
            compose_session = StageSession(
                "gen-compose",
                os.path.join(output_dir, "sessions", "gen_compose"),
            )

            metadata = {
                "cve_id": cve_id,
                "language": language,
                "repo_path": repo_path,
                "ir_root": ir_case_dir,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "backend": "codex",
                "model": self.backend.model,
                "ablation_mode": self.backend.ablation_mode,
                "session_architecture": {
                    "gen_fragments": "shared native Codex session when available, with virtual replay fallback",
                    "gen_compose": "isolated native Codex session when available, with virtual replay fallback",
                },
            }
            _write_json(os.path.join(output_dir, "metadata.json"), metadata)

            l1_json = json.dumps(l1, indent=2, ensure_ascii=False)
            l2_json = json.dumps(l2, indent=2, ensure_ascii=False)
            l3_json = json.dumps(l3, indent=2, ensure_ascii=False)

            fragment_bundle = {
                "case_id": cve_id,
                "language": language,
                "fragments": [],
            }

            for index, step in enumerate(steps, start=1):
                step_id = step.get("step_id", f"step_{index}")
                slug = _slugify(step_id)
                retrieval_plan = build_step_retrieval_plan(step, language, task.nvd_cache)
                step_output_dir = os.path.join(fragments_dir, f"{index:02d}_{slug}")
                os.makedirs(step_output_dir, exist_ok=True)
                _write_json(os.path.join(step_output_dir, "retrieval_plan.json"), retrieval_plan)
                _write_json(os.path.join(step_output_dir, "step.json"), step)

                prompt = vulnsynth_prompts.build_fragment_prompt(
                    task,
                    l1_json,
                    l2_json,
                    l3_json,
                    json.dumps(step, indent=2, ensure_ascii=False),
                    json.dumps(retrieval_plan, indent=2, ensure_ascii=False),
                    language,
                )
                fragment = await self._run_stage(
                    f"gen_step_{index:02d}_{slug}",
                    prompt,
                    step_output_dir,
                    session=fragments_session,
                )
                _write_json(os.path.join(step_output_dir, "fragment.json"), fragment)
                fragment_code = str(fragment.get("codeql_fragment", "")).rstrip() + "\n"
                _write_text(os.path.join(step_output_dir, "fragment.qlfrag"), fragment_code)
                fragment_bundle["fragments"].append(fragment)

            fragment_bundle_path = os.path.join(output_dir, "fragment_bundle.json")
            _write_json(fragment_bundle_path, fragment_bundle)

            compose_prompt = vulnsynth_prompts.build_query_composition_prompt(
                task,
                l1_json,
                l2_json,
                l3_json,
                json.dumps(fragment_bundle, indent=2, ensure_ascii=False),
                language,
            )
            final_query = await self._run_stage(
                "compose_final_query",
                compose_prompt,
                output_dir,
                session=compose_session,
            )
            _write_json(os.path.join(output_dir, "final_query.json"), final_query)

            query_file_name = final_query.get("query_file_name") or f"{cve_id.lower()}_generated.ql"
            if not str(query_file_name).endswith(".ql"):
                query_file_name = f"{query_file_name}.ql"
            query_path = os.path.join(output_dir, query_file_name)
            _write_text(query_path, str(final_query.get("query_code", "")).rstrip() + "\n")

            self.logger.info("Starting post-generation compile and execution stage")
            validation = await _compile_and_run_generated_query(
                cve_id=cve_id,
                cve_dir=cve_dir,
                query_path=query_path,
                language=language,
                output_dir=output_dir,
                logger=self.logger,
            )

            return {
                "output_dir": output_dir,
                "fragments_dir": fragments_dir,
                "fragment_bundle_path": fragment_bundle_path,
                "final_query_json_path": os.path.join(output_dir, "final_query.json"),
                "final_query_path": query_path,
                "qlpack_path": validation["qlpack_path"],
                "compilation_summary_path": validation.get("compilation_summary_path"),
                "compilation_success": validation.get("compilation_success", False),
                "execution_result_path": validation["execution_result_path"],
                "execution_success": validation.get("execution_success", False),
                "execution_skipped": validation.get("execution_skipped", False),
            }
        finally:
            self.logger.info("Cleaning up MCP/LSP processes after gen stage")
            await self.backend.cleanup()


async def main() -> None:
    parser = argparse.ArgumentParser(description="VulnSynth plan/gen agent")
    parser.add_argument("--mode", default="plan", choices=["plan", "gen", "all"])
    parser.add_argument("--cve-id", required=True, help="CVE identifier")
    parser.add_argument("--output-root", default="src/IR", help="Relative output root directory")
    parser.add_argument("--ir-root", default=None, help="IR root for gen mode; defaults to --output-root")
    parser.add_argument("--generation-subdir", default="generated_query", help="Subdirectory for gen outputs under the IR case directory")
    parser.add_argument("--model", default="gpt-5", help="Codex model id")
    parser.add_argument("--ablation-mode", default="full", choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"])
    parser.add_argument("--working-dir", default=None, help="Workspace root; defaults to repository root")
    parser.add_argument("--compile-query", action="store_true", help="Compile-check the generated CodeQL query")
    parser.add_argument("--codeql-path", default=os.environ.get("CODEQL_PATH", ""), help="Path to the CodeQL CLI executable")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    ir_root = args.ir_root or args.output_root

    if args.mode in ("plan", "all"):
        plan_agent = VulnSynthPlanAgent(
            working_dir=args.working_dir,
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
        print(f"qlpack: {gen_result['qlpack_path']}")
        print(f"Compilation summary: {gen_result['compilation_summary_path']}")
        print(f"Compilation success: {gen_result['compilation_success']}")
        print(f"Execution result: {gen_result['execution_result_path']}")
        print(f"Execution success: {gen_result['execution_success']}")
        if gen_result["execution_skipped"]:
            print("Execution stage was skipped because compilation failed")
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


if __name__ == "__main__":
    asyncio.run(main())
