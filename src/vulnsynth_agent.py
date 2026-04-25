#!/usr/bin/env python3

import argparse
import asyncio
import csv
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


# Allow running as `python src/vulnsynth_agent.py ...`
SRC_DIR = Path(__file__).resolve().parent
ROOT_DIR = SRC_DIR.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agent_backends import create_backend
from agent_backends.codex_backend import CodexBackend

# Avoid importing src/config.py because it depends on chromadb/sqlite.
PROJECT_INFO = str(ROOT_DIR / "data" / "project_info.csv")
CVES_PATH = str(ROOT_DIR / "cves")


@dataclass
class PlanIRTask:
    cve_id: str
    cwe_id: str
    cwe_name: str
    repo_name: str
    github_url: str
    buggy_commit_id: str
    fix_commit_id: str
    repo_path: str
    diff_path: str
    fix_commit_diff: str


def _load_project_info_row(cve_id: str, csv_path: str) -> Dict[str, str]:
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("cve_id") == cve_id:
                return row
    raise FileNotFoundError(f"CVE not found in project_info.csv: {cve_id}")


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _write_json(path: str, obj: object) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def _coerce_fix_commit_id(fix_commit_ids: str) -> str:
    # project_info.csv stores fix commits as semicolon-separated list.
    if not fix_commit_ids:
        return ""
    parts = [p.strip() for p in fix_commit_ids.split(";") if p.strip()]
    return parts[0] if parts else ""


def _build_task(cve_id: str) -> PlanIRTask:
    row = _load_project_info_row(cve_id, PROJECT_INFO)

    repo_name = row.get("github_repository_name", "").strip()
    github_url = row.get("github_url", "").strip()
    buggy_commit_id = row.get("buggy_commit_id", "").strip()
    fix_commit_id = _coerce_fix_commit_id(row.get("fix_commit_ids", ""))
    cwe_id = row.get("cwe_id", "").strip()
    cwe_name = row.get("cwe_name", "").strip()

    if not repo_name:
        raise ValueError(f"Missing github_repository_name for {cve_id}")

    cve_dir = os.path.join(CVES_PATH, cve_id)
    repo_path = os.path.join(cve_dir, repo_name)
    diff_path = os.path.join(cve_dir, f"{cve_id}.diff")

    if not os.path.exists(repo_path):
        raise FileNotFoundError(
            f"Repo directory not found: {repo_path}. "
            f"Expected it under CVES_PATH={CVES_PATH}."
        )
    if not os.path.exists(diff_path):
        raise FileNotFoundError(
            f"Diff file not found: {diff_path}. "
            "Run scripts/get_cve_repos.py to generate it."
        )

    diff_text = _read_text(diff_path)

    return PlanIRTask(
        cve_id=cve_id,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        repo_name=repo_name,
        github_url=github_url,
        buggy_commit_id=buggy_commit_id,
        fix_commit_id=fix_commit_id,
        repo_path=repo_path,
        diff_path=diff_path,
        fix_commit_diff=diff_text,
    )


async def run_plan_agent(
    task: PlanIRTask,
    output_dir: str,
    model: str,
    ablation_mode: str,
    codex_use_local_config: bool,
) -> Dict[str, object]:
    logger = logging.getLogger("vulnsynth_agent")
    backend = create_backend(
        agent_type="codex",
        model=model,
        logger=logger,
        ablation_mode=ablation_mode,
        use_local_config=codex_use_local_config,
    )

    backend.setup_workspace(output_dir, task)

    if not isinstance(backend, CodexBackend):
        raise RuntimeError("Plan agent currently requires CodexBackend")
    prompt = backend.create_plan_ir_prompt(task)

    # Do not force login. If credentials are present in the environment,
    # Codex can consume them directly.
    env = dict(os.environ)
    env["CODEX_USE_LOCAL_CONFIG"] = "1" if codex_use_local_config else "0"

    result = await backend.execute_prompt(
        prompt=prompt,
        env=env,
        cwd=output_dir,
        phase_name="plan_ir",
    )

    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    # Preferred: robust extraction from mixed JSONL output.
    obj = backend.extract_plan_ir_json(stdout)
    if obj is None:
        # Fallback: try extracting assistant text then parsing JSON.
        text = backend.extract_text_output(stdout)
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            rc = result.get("returncode", None)
            stdout_tail = "\n".join(stdout.splitlines()[-80:])
            stderr_tail = "\n".join(stderr.splitlines()[-80:])
            raise RuntimeError(
                "Plan agent did not return a parsable JSON bundle (expected top-level keys: l1,l2,l3). "
                f"returncode={rc}. JSON parse error: {e}\n\n"
                f"STDOUT (tail):\n{stdout_tail}\n\nSTDERR (tail):\n{stderr_tail}"
            )

    if not isinstance(obj, dict) or not all(k in obj for k in ("l1", "l2", "l3")):
        raise RuntimeError(
            "Plan agent JSON must contain top-level keys: l1, l2, l3"
        )
    return obj


async def main_async() -> int:
    parser = argparse.ArgumentParser(description="VulnSynth multi-agent runner (plan agent only)")
    parser.add_argument("--cve-id", required=True, help="CVE identifier, e.g. CVE-2025-27818")
    parser.add_argument("--output-root", default=None, help="Output root directory (default: src/cve_ir)")
    parser.add_argument("--model", default="gpt-5", help="Codex model id (ignored when using local codex config)")
    parser.add_argument(
        "--ablation-mode",
        default="no_tools",
        choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"],
        help="Agent ablation mode",
    )
    parser.add_argument(
        "--codex-use-local-config",
        action="store_true",
        default=True,
        help="Use local Codex CLI config and skip login/model override",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    task = _build_task(args.cve_id)

    src_dir = Path(__file__).resolve().parent
    output_root = args.output_root or str(src_dir / "cve_ir")
    case_out_dir = os.path.join(output_root, task.cve_id)
    _ensure_dir(case_out_dir)

    ir_obj = await run_plan_agent(
        task=task,
        output_dir=case_out_dir,
        model=args.model,
        ablation_mode=args.ablation_mode,
        codex_use_local_config=args.codex_use_local_config,
    )

    l1_path = os.path.join(case_out_dir, "L1_fact.json")
    l2_path = os.path.join(case_out_dir, "L2_schema_ir.json")
    l3_path = os.path.join(case_out_dir, "L3_logic_plan.json")
    bundle_path = os.path.join(case_out_dir, "IR_bundle.json")

    _write_json(l1_path, ir_obj["l1"])
    _write_json(l2_path, ir_obj["l2"])
    _write_json(l3_path, ir_obj["l3"])
    _write_json(bundle_path, ir_obj)

    print(f"Wrote L1: {l1_path}")
    print(f"Wrote L2: {l2_path}")
    print(f"Wrote L3: {l3_path}")
    print(f"Wrote bundle: {bundle_path}")
    return 0


def main() -> int:
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
