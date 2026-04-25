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
import sys
import tempfile
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

    async def _run_stage(
        self,
        stage_name: str,
        prompt: str,
        output_dir: str,
    ) -> Dict[str, Any]:
        prompt_path = os.path.join(output_dir, f"{stage_name}_prompt.md")
        _write_text(prompt_path, prompt)

        result = await self.backend.execute_prompt(
            prompt=prompt,
            env=os.environ.copy(),
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
        _write_json(os.path.join(output_dir, "cve_facts.json"), l1)

        self.logger.info("Stage 2/3: generating L2 schema IR")
        l2 = await self._run_stage(
            "stage2_l2",
            vulnsynth_prompts.build_l2_prompt(task, json.dumps(l1, indent=2, ensure_ascii=False)),
            output_dir,
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
        self.backend.setup_workspace(output_dir, task)

        l1_path = os.path.join(output_dir, "cve_facts.json")
        l2_path = os.path.join(output_dir, "codeql_schema_ir.json")
        l3_path = os.path.join(output_dir, "codeql_logic_steps.json")

        l1: Dict[str, Any]
        l2: Dict[str, Any]

        if rerun_l1 or not os.path.exists(l1_path):
            self.logger.info("Plan partial: regenerating L1")
            l1 = await self._run_stage("stage1_l1", vulnsynth_prompts.build_l1_prompt(task), output_dir)
            _write_json(l1_path, l1)
        else:
            l1 = _read_json(l1_path)

        if rerun_l2 or rerun_l1 or not os.path.exists(l2_path):
            self.logger.info("Plan partial: regenerating L2")
            l2 = await self._run_stage(
                "stage2_l2",
                vulnsynth_prompts.build_l2_prompt(task, json.dumps(l1, indent=2, ensure_ascii=False)),
                output_dir,
            )
            _write_json(l2_path, l2)
        else:
            l2 = _read_json(l2_path)

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

        result = await self.backend.execute_prompt(
            prompt=prompt,
            env=os.environ.copy(),
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
        return parsed

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

        l1_json = json.dumps(l1, indent=2, ensure_ascii=False)
        l2_json = json.dumps(l2, indent=2, ensure_ascii=False)
        l3_json = json.dumps(l3, indent=2, ensure_ascii=False)

        rerun_steps_set = set(rerun_steps or [])

        fragment_bundle: Dict[str, Any] = {
            "case_id": cve_id,
            "language": language,
            "fragments": [],
        }

        existing_bundle_path = os.path.join(output_dir, "fragment_bundle.json")
        if reuse_existing_fragments and not rerun_steps_set and os.path.exists(existing_bundle_path):
            try:
                existing_bundle = _read_json(existing_bundle_path)
                if isinstance(existing_bundle, dict) and isinstance(existing_bundle.get("fragments"), list):
                    fragment_bundle["fragments"] = existing_bundle.get("fragments", [])
                    # Preserve any out-of-band feedback injected by the loop controller.
                    for k in ("feedback", "feedback_history"):
                        if k in existing_bundle:
                            fragment_bundle[k] = existing_bundle[k]
            except Exception:
                pass

        need_generate_any_fragments = not fragment_bundle.get("fragments") or bool(rerun_steps_set)

        if need_generate_any_fragments:
            # Rebuild fragment list deterministically in step order.
            fragment_bundle["fragments"] = []

        for index, step in enumerate(steps, start=1):
            step_id = step.get("step_id", f"step_{index}")
            slug = _slugify(step_id)
            retrieval_plan = build_step_retrieval_plan(step, language, task.nvd_cache)
            step_output_dir = os.path.join(fragments_dir, f"{index:02d}_{slug}")
            os.makedirs(step_output_dir, exist_ok=True)
            _write_json(os.path.join(step_output_dir, "retrieval_plan.json"), retrieval_plan)
            _write_json(os.path.join(step_output_dir, "step.json"), step)

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
                except Exception:
                    should_rerun = True

            if should_rerun:
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
                )
                _write_json(fragment_path, fragment)
                fragment_code = str(fragment.get("codeql_fragment", "")).rstrip() + "\n"
                _write_text(os.path.join(step_output_dir, "fragment.qlfrag"), fragment_code)

            fragment_bundle["fragments"].append(fragment)

        fragment_bundle_path = os.path.join(output_dir, "fragment_bundle.json")
        _write_json(fragment_bundle_path, fragment_bundle)

        final_query_json_path = os.path.join(output_dir, "final_query.json")
        if rerun_composer:
            compose_prompt = vulnsynth_prompts.build_query_composition_prompt(
                task,
                l1_json,
                l2_json,
                l3_json,
                json.dumps(fragment_bundle, indent=2, ensure_ascii=False),
                language,
            )
            final_query = await self._run_stage("compose_final_query", compose_prompt, output_dir)
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
        if not os.path.exists(query_path):
            # Fallback: if the file name differs, pick the first .ql in gen_dir.
            ql_files = [p for p in os.listdir(gen_dir) if p.endswith(".ql")]
            if not ql_files:
                raise FileNotFoundError(f"No .ql file found in {gen_dir}")
            query_path = os.path.join(gen_dir, sorted(ql_files)[0])

        # Discover vuln/fix DBs.
        vuln_db, fixed_db = _discover_codeql_db_paths(cve_id)

        cve_dir, repo_path, _ = discover_cve_paths(cve_id)
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
            if vuln_results == 0:
                _add(
                    "empty_result_on_vulnerable",
                    "high",
                    0.8,
                    ["compile success", "vulnerable results == 0"],
                    ["l3", "fragment", "composer"],
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
                # MVP: no evaluator integration here
                "recall_method": None,
                "recall_file": None,
                "false_positive_on_fixed": fixed_results > 0,
            },
            "primary_failure_type": primary,
            "classified_failures": classified,
        }
        return report


class UpdateEngine:
    """Applies explicit update actions to L1/L2/L3 (MVP: mainly updates L3 retrieval hints)."""

    def derive_actions(
        self,
        *,
        failure_report: dict,
        l1: dict,
        l2: dict,
        l3: dict,
        failure_repeat_count: int = 1,
    ) -> dict:
        actions: List[dict] = []
        failures = failure_report.get("classified_failures", [])
        iteration = int(failure_report.get("iteration", 0) or 0)
        case_id = str(failure_report.get("case_id") or "")
        primary = failure_report.get("primary_failure_type")

        def _act(action_id: str, target_layer: str, target_object_id: str, action_type: str, reason: str, patch: dict | None = None):
            obj = {
                "action_id": action_id,
                "target_layer": target_layer,
                "target_object_id": target_object_id,
                "action_type": action_type,
                "reason": reason,
            }
            if patch is not None:
                obj["patch"] = patch
            actions.append(obj)

        # MVP+ action set aligned with design doc section 15/18.
        for idx, f in enumerate(failures, start=1):
            ft = f.get("failure_type")

            if ft in ("syntax_error", "fragment_composition_conflict"):
                _act(
                    f"act_{idx:03d}",
                    "Composer",
                    "compose_final_query",
                    "recompose_query",
                    f"{ft}: adjust composer output / de-duplicate definitions",
                )
            elif ft == "missing_import":
                _act(
                    f"act_{idx:03d}",
                    "Composer",
                    "compose_final_query",
                    "recompose_query",
                    "missing_import: ensure required imports appear in final query",
                )
            elif ft in ("unresolved_codeql_symbol", "retrieval_miss"):
                _act(
                    f"act_{idx:03d}",
                    "L3",
                    "*",
                    "augment_retrieval_hints",
                    f"{ft}: broaden retrieval hints to reduce API hallucination",
                    patch={
                        "candidate_classes_add": [
                            "Expr",
                            "MethodCall",
                            "Call",
                            "FieldAccess",
                            "VarAccess",
                            "IfStmt",
                            "ThrowStmt",
                            "StringLiteral",
                        ],
                        "candidate_predicates_add": [
                            "hasQualifiedName",
                            "hasName",
                            "getMethod",
                            "getQualifier",
                            "getArgument",
                            "getEnclosingCallable",
                            "getInitializer",
                        ],
                    },
                )
                _act(
                    f"act_{idx:03d}_b",
                    "Fragment",
                    "*",
                    "regenerate_fragment",
                    "Regenerate fragments after L3 retrieval hints update",
                )
            elif ft in ("wrong_predicate_arity", "wrong_type_constraint"):
                _act(
                    f"act_{idx:03d}",
                    "Fragment",
                    "*",
                    "regenerate_fragment",
                    f"{ft}: regenerate fragment(s) with corrected CodeQL typing/arity",
                )
            elif ft == "empty_result_on_vulnerable":
                # First: relax by improving L3 guidance; after repeats, escalate to L3 rebuild.
                _act(
                    f"act_{idx:03d}",
                    "L3",
                    "*",
                    "revise_step_description",
                    "empty_result_on_vulnerable: relax constraints; ensure anchor steps exist",
                )
                if failure_repeat_count >= 2:
                    _act(
                        f"act_{idx:03d}_b",
                        "L3",
                        "*",
                        "split_step",
                        "Repeated empty results: consider rebuilding/splitting steps",
                    )
                _act(
                    f"act_{idx:03d}_c",
                    "Composer",
                    "compose_final_query",
                    "recompose_query",
                    "Recompose query after L3 guidance update",
                )
            elif ft == "false_positive_on_fixed":
                _act(
                    f"act_{idx:03d}",
                    "L2",
                    "*",
                    "add_guard",
                    "false_positive_on_fixed: add guard/constraint to exclude fixed behavior",
                )
                _act(
                    f"act_{idx:03d}_b",
                    "L3",
                    "*",
                    "add_step",
                    "Add exclusion/sanitizer step",
                )
            elif ft == "database_analyze_failure":
                _act(
                    f"act_{idx:03d}",
                    "Environment",
                    "codeql",
                    "retry_validate",
                    "database_analyze_failure: retry validate; likely environment issue",
                )

        return {
            "case_id": case_id,
            "iteration": iteration,
            "primary_failure_type": primary,
            "failure_repeat_count": failure_repeat_count,
            "actions": actions,
        }

    def apply_actions(self, *, l1: dict, l2: dict, l3: dict, update_actions: dict) -> tuple[dict, dict, dict]:
        # MVP: modifies L3 retrieval hints / expected output and attaches feedback history.
        actions = update_actions.get("actions", [])
        l1_u = json.loads(json.dumps(l1))
        l2_u = json.loads(json.dumps(l2))
        l3_u = json.loads(json.dumps(l3))

        fb_entry = {
            "iteration": int(update_actions.get("iteration", 0) or 0),
            "primary_failure_type": update_actions.get("primary_failure_type"),
            "actions": [a.get("action_type") for a in actions],
        }
        for obj in (l1_u, l2_u, l3_u):
            hist = obj.setdefault("feedback_history", [])
            if isinstance(hist, list):
                hist.append(fb_entry)

        steps = l3_u.get("steps", [])

        def _ensure_list(container: dict, key: str) -> list:
            v = container.get(key)
            if isinstance(v, list):
                return v
            container[key] = []
            return container[key]

        for act in actions:
            if act.get("target_layer") == "L3" and act.get("action_type") == "augment_retrieval_hints":
                patch = act.get("patch", {}) or {}
                add_classes = patch.get("candidate_classes_add", [])
                add_preds = patch.get("candidate_predicates_add", [])
                for step in steps:
                    hints = step.setdefault("retrieval_hints", {})
                    cls_list = _ensure_list(hints, "candidate_classes")
                    pred_list = _ensure_list(hints, "candidate_predicates")
                    for c in add_classes:
                        if c not in cls_list:
                            cls_list.append(c)
                    for p in add_preds:
                        if p not in pred_list:
                            pred_list.append(p)
                    notes = step.setdefault("notes", [])
                    if isinstance(notes, list):
                        notes.append("FeedbackLoop: broadened retrieval_hints due to unresolved CodeQL symbol")
            elif act.get("target_layer") == "L3" and act.get("action_type") == "revise_step_description":
                for step in steps:
                    exp = step.get("expected_output")
                    extra = "FeedbackLoop: avoid over-constraining; prefer binding anchors then refining"
                    if isinstance(exp, str) and extra not in exp:
                        step["expected_output"] = exp + "\n" + extra
                    elif not exp:
                        step["expected_output"] = extra
        return l1_u, l2_u, l3_u


class RegenPlanner:
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

        if ft in ("unknown_failure", "failure_oscillation"):
            mode = "fallback_replan_from_l1" if failure_repeat_count < 2 else "fallback_full_replan_from_inputs"
            return {
                "case_id": case_id,
                "iteration": iteration,
                "primary_failure_type": ft,
                "failure_repeat_count": failure_repeat_count,
                "rerun_scope": {"mode": mode},
                "reason": f"{ft}: fallback regen mode",
                "drop_artifacts": [
                    "current_l2",
                    "current_l3",
                    "current_fragments",
                    "current_query",
                ]
                + (["current_l1"] if mode == "fallback_full_replan_from_inputs" else []),
                "preserve_artifacts": ["validation_history", "state_trace"],
            }

        # Default: rerun composer only.
        scope = {
            "rerun_l1": False,
            "rerun_l2": False,
            "rerun_l3": False,
            "rerun_steps": [],
            "rerun_all_fragments": False,
            "rerun_composer": True,
        }

        if ft in ("syntax_error", "fragment_composition_conflict", "missing_import", "weak_reporting_anchor"):
            scope["rerun_composer"] = True
        elif ft in ("unresolved_codeql_symbol", "wrong_predicate_arity", "wrong_type_constraint", "retrieval_miss", "retrieval_over_bias"):
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2 and ft in ("unresolved_codeql_symbol", "wrong_type_constraint"):
                scope["rerun_l2"] = True
                scope["rerun_l3"] = True
        elif ft in ("query_runtime_failure",):
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2:
                scope["rerun_l3"] = True
        elif ft in ("database_analyze_failure",):
            # Environment issue: retry validate only.
            scope = {
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
                scope["rerun_l3"] = True
                scope["rerun_all_fragments"] = True
            else:
                scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
        elif ft in ("false_positive_on_fixed",):
            scope["rerun_all_fragments"] = True
            scope["rerun_composer"] = True
            if failure_repeat_count >= 2:
                scope["rerun_l2"] = True
                scope["rerun_l3"] = True
                scope["rerun_all_fragments"] = True
        else:
            # Unknown: be conservative
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
        _ensure_dir(self._feedback_dir(cve_id))

        trace_path = os.path.join(self._feedback_dir(cve_id), "state_trace.jsonl")
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

        # Ensure plan exists.
        l1_path, l2_path, l3_path = _load_case_ir_paths(ir_case_dir)
        if not (os.path.exists(l1_path) and os.path.exists(l2_path) and os.path.exists(l3_path)):
            plan_agent = VulnSynthPlanAgent(
                working_dir=self.working_dir,
                agent=self.agent,
                model=self.model,
                ablation_mode=self.ablation_mode,
                codex_use_local_config=True,
            )
            await plan_agent.analyze(cve_id, output_root=self.ir_root)
        _trace("plan_ok", "GEN_QUERY", {"ir_case_dir": ir_case_dir})

        # Ensure gen exists.
        gen_dir = os.path.join(ir_case_dir, self.generation_subdir)
        final_query_json_path = os.path.join(gen_dir, "final_query.json")
        if not os.path.exists(final_query_json_path):
            gen_agent = VulnSynthGenAgent(
                working_dir=self.working_dir,
                agent=self.agent,
                model=self.model,
                ablation_mode=self.ablation_mode,
                codex_use_local_config=True,
            )
            await gen_agent.generate(cve_id, ir_root=self.ir_root, generation_subdir=self.generation_subdir)
        _trace("gen_ok", "VALIDATE_COMPILE", {"generated_query_dir": gen_dir})

        valid_agent = VulnSynthValidAgent(working_dir=self.working_dir)

        last_summary_path = ""
        last_primary_failure = None
        repeat_count = 0
        recent_failures: List[str] = []
        for iteration in range(1, self.max_iters + 1):
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
                return {"status": "success", "iterations": iteration, "summary_path": last_summary_path}

            # Failure path: analyze + update + plan selective regeneration
            _trace("eval_fail", "ANALYZE_FAILURE", {"summary_path": last_summary_path})
            l1, l2, l3 = _load_case_ir(ir_case_dir)
            failure_report = self.analyzer.analyze(case_id=cve_id, iteration=iteration, validation_summary=validation_summary)
            _write_json(os.path.join(iter_dir, "failure_report.json"), failure_report)

            primary = failure_report.get("primary_failure_type")

            # Detect oscillation in primary failure types (doc section 19.2 T2).
            if primary:
                recent_failures.append(str(primary))
                recent_failures = recent_failures[-4:]
                if len(recent_failures) >= 4 and len(set(recent_failures)) >= 3:
                    primary = "failure_oscillation"

            if primary and primary == last_primary_failure:
                repeat_count += 1
            else:
                last_primary_failure = primary
                repeat_count = 1
            _trace("analyze_ok", "APPLY_UPDATE", {"primary_failure_type": primary, "repeat_count": repeat_count})

            update_actions = self.updater.derive_actions(
                failure_report=failure_report,
                l1=l1,
                l2=l2,
                l3=l3,
                failure_repeat_count=repeat_count,
            )
            _write_json(os.path.join(iter_dir, "update_actions.json"), update_actions)

            l1_u, l2_u, l3_u = self.updater.apply_actions(l1=l1, l2=l2, l3=l3, update_actions=update_actions)
            _write_json(os.path.join(iter_dir, "updated_l1.json"), l1_u)
            _write_json(os.path.join(iter_dir, "updated_l2.json"), l2_u)
            _write_json(os.path.join(iter_dir, "updated_l3.json"), l3_u)

            # Write updated IR back as current working version.
            _write_case_ir(ir_case_dir, l1_u, l2_u, l3_u)

            regen_plan = self.planner.build_regen_plan(
                case_id=cve_id,
                iteration=iteration,
                update_actions=update_actions,
                primary_failure_type=primary,
                failure_repeat_count=repeat_count,
            )
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

                plan_agent = VulnSynthPlanAgent(
                    working_dir=self.working_dir,
                    agent=self.agent,
                    model=self.model,
                    ablation_mode=self.ablation_mode,
                    codex_use_local_config=True,
                )
                await plan_agent.analyze(cve_id, output_root=self.ir_root)

                gen_agent = VulnSynthGenAgent(
                    working_dir=self.working_dir,
                    agent=self.agent,
                    model=self.model,
                    ablation_mode=self.ablation_mode,
                    codex_use_local_config=True,
                )
                _trace("rerun_gen", "GEN_QUERY", {"mode": mode})
                await gen_agent.generate(
                    cve_id,
                    ir_root=self.ir_root,
                    generation_subdir=self.generation_subdir,
                    rerun_steps=["*"],
                    rerun_composer=True,
                    reuse_existing_fragments=False,
                )
                _trace("gen_ok", "VALIDATE_COMPILE")
                continue

            # PLAN regeneration (L1/L2/L3)
            if scope.get("rerun_l1") or scope.get("rerun_l2") or scope.get("rerun_l3"):
                _trace("rerun_plan", "PLAN_READY", scope)
                plan_agent = VulnSynthPlanAgent(
                    working_dir=self.working_dir,
                    agent=self.agent,
                    model=self.model,
                    ablation_mode=self.ablation_mode,
                    codex_use_local_config=True,
                )
                await plan_agent.analyze_partial(
                    cve_id,
                    output_root=self.ir_root,
                    rerun_l1=bool(scope.get("rerun_l1")),
                    rerun_l2=bool(scope.get("rerun_l2")),
                    rerun_l3=bool(scope.get("rerun_l3")),
                )
                _trace("plan_ok", "GEN_QUERY")

            gen_agent = VulnSynthGenAgent(
                working_dir=self.working_dir,
                agent=self.agent,
                model=self.model,
                ablation_mode=self.ablation_mode,
                codex_use_local_config=True,
            )
            _trace("rerun_gen", "GEN_QUERY", scope)
            await gen_agent.generate(
                cve_id,
                ir_root=self.ir_root,
                generation_subdir=self.generation_subdir,
                rerun_steps=scope.get("rerun_steps") if scope.get("rerun_steps") else (["*"] if scope.get("rerun_all_fragments") else []),
                rerun_composer=bool(scope.get("rerun_composer", True)),
                reuse_existing_fragments=not bool(scope.get("rerun_all_fragments")),
            )
            _trace("gen_ok", "VALIDATE_COMPILE")

        _trace("budget_exhausted", "TERMINAL_FAIL", {"summary_path": last_summary_path})
        final_fail = {
            "status": "failed",
            "iterations": self.max_iters,
            "summary_path": last_summary_path,
            "primary_failure_type": last_primary_failure,
            "repeat_count": repeat_count,
        }
        _write_json(os.path.join(self._feedback_dir(cve_id), "final_failure_summary.json"), final_fail)
        return final_fail


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
    parser.add_argument("--codeql-path", default=os.environ.get("CODEQL_PATH", ""), help="Path to the CodeQL CLI executable")
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


if __name__ == "__main__":
    asyncio.run(main())
