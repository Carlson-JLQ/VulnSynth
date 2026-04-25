#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

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


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


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
        parsed = _extract_json_object(text_output)
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


async def main() -> None:
    parser = argparse.ArgumentParser(description="VulnSynth plan agent")
    parser.add_argument("--cve-id", required=True, help="CVE identifier")
    parser.add_argument("--output-root", default="src/IR", help="Relative output root directory")
    parser.add_argument("--model", default="gpt-5", help="Codex model id")
    parser.add_argument("--ablation-mode", default="full", choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"])
    parser.add_argument("--working-dir", default=None, help="Workspace root; defaults to repository root")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    agent = VulnSynthPlanAgent(
        working_dir=args.working_dir,
        model=args.model,
        ablation_mode=args.ablation_mode,
        codex_use_local_config=True,
    )

    result = await agent.analyze(args.cve_id, output_root=args.output_root)
    print("VulnSynth plan generation completed")
    print(f"Output directory: {result['output_dir']}")
    print(f"L1: {result['l1_path']}")
    print(f"L2: {result['l2_path']}")
    print(f"L3: {result['l3_path']}")


if __name__ == "__main__":
    asyncio.run(main())
