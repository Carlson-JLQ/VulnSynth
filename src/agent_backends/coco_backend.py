import asyncio
import json
import os
import shutil
from typing import Dict, Optional

from . import AgentBackend
from . import codex_prompts as prompts


MODELS = {
    # Keep a minimal alias map; Coco can also use whatever is configured locally.
    "gpt-5": "gpt-5",
    "gpt-5.4": "gpt-5.4",
}


class CocoBackend(AgentBackend):

    def __init__(
        self,
        model: str,
        logger,
        ablation_mode: str = "full",
        use_local_config: bool = True,
    ):
        super().__init__(model, logger, ablation_mode=ablation_mode)
        self.cli_path = os.environ.get("COCO_PATH", shutil.which("coco") or "coco")
        self.use_local_config = use_local_config

    def get_tool_prefix(self) -> str:
        # Prompts in this repo currently reference tools like `chroma_query_documents`
        # without an MCP prefix, so keep empty to match that convention.
        return ""

    def get_codeql_tool_prefix(self) -> str:
        return ""

    @staticmethod
    def extract_text_output(stdout: str) -> str:
        """Extract assistant text from `coco -p --json` output.

        Falls back to raw stdout for non-JSON runs.
        """
        try:
            data = json.loads(stdout)
            msg = data.get("message", {}) if isinstance(data, dict) else {}
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
        except Exception:
            pass
        return stdout.strip()

    def parse_usage(self, stdout: str) -> Dict:
        usage = {
            "total_cost_usd": 0.0,
            "total_input_tokens": 0,
            "total_cache_creation_tokens": 0,
            "total_cache_read_tokens": 0,
            "total_output_tokens": 0,
            "total_reasoning_tokens": 0,
            "sessions_count": 0,
            "parsing_errors": [],
        }
        try:
            data = json.loads(stdout)
            msg = data.get("message", {}) if isinstance(data, dict) else {}
            meta = msg.get("response_meta", {}) if isinstance(msg, dict) else {}
            u = meta.get("usage", {}) if isinstance(meta, dict) else {}
            usage["total_input_tokens"] = int(u.get("prompt_tokens", 0) or 0)
            usage["total_output_tokens"] = int(u.get("completion_tokens", 0) or 0)
            usage["total_cache_read_tokens"] = int(
                (u.get("prompt_token_details", {}) or {}).get("cached_tokens", 0) or 0
            )
            usage["sessions_count"] = 1
        except Exception as e:
            usage["parsing_errors"].append(f"Failed to parse Coco usage: {e}")
        return usage

    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        # Coco reads user/project configuration from ~/.trae / project-level configs.
        # MCP servers are managed outside this repo via `coco mcp ...`.
        return None

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        """Run a single prompt through Coco CLI in print mode."""
        model_id = MODELS.get(self.model, self.model)

        cmd = [
            self.cli_path,
            "--yolo",
            "-p",
            "--json",
        ]

        # Reuse a stable session id when provided. This helps avoid creating a new
        # Coco session for every stage/iteration (and may reduce background resource churn).
        session_id = str(env.get("COCO_SESSION_ID", "")).strip()
        if session_id:
            cmd.extend(["--session-id", session_id])

        # Optional: resume a specific session id (or AUTO).
        resume = str(env.get("COCO_RESUME", "")).strip()
        if resume:
            cmd.extend(["--resume", resume])

        # Allow callers to override config per invocation.
        # Always keep plugin sync disabled to avoid hangs in restricted networks.
        cmd.extend(["-c", "features.remote_plugin_sync=false"])

        if not self.use_local_config and model_id:
            cmd.extend(["-c", f"model={model_id}"])

        # Optional timeout control (seconds). Coco accepts duration strings.
        timeout_sec = str(env.get("COCO_QUERY_TIMEOUT_SEC", "")).strip()
        if timeout_sec.isdigit() and int(timeout_sec) > 0:
            cmd.extend(["--query-timeout", f"{timeout_sec}s"])

        # Provide prompt as positional arg to avoid stdin edge cases.
        cmd.append(prompt)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await proc.communicate()
            stdout_s = stdout_b.decode("utf-8", errors="replace")
            stderr_s = stderr_b.decode("utf-8", errors="replace")
            return {
                "stdout": stdout_s,
                "stderr": stderr_s,
                "returncode": proc.returncode,
                "api_usage": self.parse_usage(stdout_s),
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }

    # Prompt generation (reuse Codex prompt templates for now)

    def create_phase1_prompt(self, task) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase1_no_tools(task)
        return prompts.phase1_full(task)

    def create_phase3_initial_prompt(self, task, use_cache: bool, collection_name: str, phase1_output: str = "") -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase3_no_tools(task, phase1_output)
        return prompts.phase3_full(task, use_cache, collection_name)

    def create_refinement_prompt(self, task, previous_feedback: str, iteration: int, collection_name: str) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.refinement_no_tools(task, previous_feedback, iteration)
        return prompts.refinement_full(task, previous_feedback, iteration, collection_name)
