import asyncio
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from typing import Dict, Optional

from . import AgentBackend
from config import CHROMA_AUTH_TOKEN, CHROMA_HOST, CHROMA_PORT, CODEQL_LSP_MCP_PATH
from . import gemini_prompts as prompts

# Ablation modes that skip Chroma MCP setup
_NO_CHROMA_MODES = ("no_tools",)
# Ablation modes that skip CodeQL LSP MCP setup
_NO_LSP_MODES = ("no_tools",)

MODELS = {
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-2.5-flash": "gemini-2.5-flash",
}


class GeminiBackend(AgentBackend):

    def __init__(self, model: str, logger, ablation_mode: str = "full"):
        super().__init__(model, logger, ablation_mode=ablation_mode)
        self.cli_path = os.environ.get(
            "GEMINI_PATH", shutil.which("gemini") or "gemini"
        )
        # Stores task when full-mode phase3 iter 1 needs a 2-step execution
        self._phase3_part2_task = None

    def get_tool_prefix(self) -> str:
        return ""

    def get_codeql_tool_prefix(self) -> str:
        return ""

    @staticmethod
    def extract_text_output(stdout: str) -> str:
        """Extract assistant text from gemini -o json output."""
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                return data.get("response", stdout).strip()
        except Exception:
            pass
        return stdout.strip()

    def parse_usage(self, stdout: str) -> Dict:
        usage = {
            "total_input_tokens": 0,
            "total_cache_read_tokens": 0,
            "total_output_tokens": 0,
            "total_thinking_tokens": 0,
            "sessions_count": 0,
            "parsing_errors": [],
        }
        try:
            data = json.loads(stdout)
            models = data.get("stats", {}).get("models", {})
            for model_name, model_data in models.items():
                tokens = model_data.get("tokens", {})
                api = model_data.get("api", {})
                usage["total_input_tokens"] += tokens.get("prompt", 0)
                usage["total_cache_read_tokens"] += tokens.get("cached", 0)
                usage["total_output_tokens"] += tokens.get("candidates", 0)
                usage["total_thinking_tokens"] += tokens.get("thoughts", 0)
                usage["sessions_count"] += api.get("totalRequests", 0)
            self.logger.info(
                f"Parsed Gemini usage: {usage['sessions_count']} requests, "
                f"input={usage['total_input_tokens']}, "
                f"cached={usage['total_cache_read_tokens']}, "
                f"output={usage['total_output_tokens']}, "
                f"thinking={usage['total_thinking_tokens']}"
            )
        except Exception as e:
            usage["parsing_errors"].append(f"Failed to parse Gemini usage: {e}")
        return usage

    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Set up .gemini config dir and register project-scoped MCP servers."""
        self._setup_gemini_dir(output_dir)

        if self.ablation_mode in _NO_CHROMA_MODES:
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping MCP setup")
            return None

        if self.ablation_mode not in _NO_LSP_MODES:
            self._setup_project_scoped_codeql(output_dir)
        else:
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping CodeQL LSP MCP setup")

        self._setup_project_scoped_chroma(output_dir)
        return None

    async def _run_gemini(
        self,
        prompt: str,
        env: dict,
        cwd: str,
    ) -> Dict:
        """Execute a single Gemini process and return raw result."""
        model_id = MODELS.get(self.model, self.model)

        cmd = [
            self.cli_path,
            "-m", model_id,
            "--approval-mode", "yolo",
            "-o", "json",
        ]

        prompt_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
                tmp.write(prompt)
                prompt_file = tmp.name

            gemini_cmd = " ".join(shlex.quote(arg) for arg in cmd)
            cmd_str = f"timeout 300 sh -c 'cat {shlex.quote(prompt_file)} | {gemini_cmd}'"

            process = await asyncio.create_subprocess_shell(
                cmd_str,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=3600
            )

            os.unlink(prompt_file)

            stdout_str = stdout_bytes.decode("utf-8")
            stderr_str = stderr_bytes.decode("utf-8")

            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": process.returncode,
                "api_usage": self.parse_usage(stdout_str),
            }

        except Exception as e:
            self.logger.error(f"Gemini execution failed: {e}")
            if prompt_file:
                try:
                    os.unlink(prompt_file)
                except Exception:
                    pass
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }

    def _merge_api_usage(self, usage1: Dict, usage2: Dict) -> Dict:
        """Sum numeric fields from two api_usage dicts."""
        merged = {}
        for key in usage1:
            if key == "parsing_errors":
                merged[key] = usage1[key] + usage2.get(key, [])
            elif isinstance(usage1[key], (int, float)):
                merged[key] = usage1[key] + usage2.get(key, 0)
            else:
                merged[key] = usage1[key]
        return merged

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        """Execute a Gemini context window.

        For full-mode phase3 iteration 1, runs two context windows internally
        (part 1: Chroma retrieval + write query; part 2: LSP validation) and
        returns the merged result so ql_agent.py sees a single execution. 
        This is what worked at the time (~September 2025)
        """
        result = await self._run_gemini(prompt, env, cwd)

        if self._phase3_part2_task is not None:
            task = self._phase3_part2_task
            self._phase3_part2_task = None

            # Save part 1 output, stderr, and metrics before running part 2
            part1_prefix = os.path.join(cwd, f"{phase_name}_part1")

            with open(f"{part1_prefix}_output.txt", "w") as f:
                f.write(result["stdout"])

            if result["stderr"].strip():
                with open(f"{part1_prefix}_stderr.txt", "w") as f:
                    f.write(result["stderr"])

            part1_metrics = {
                "phase_name": f"{phase_name}_part1",
                "success": result["returncode"] == 0,
                "return_code": result["returncode"],
                "character_count": len(result["stdout"]),
                "stderr_characters": len(result["stderr"]),
                "output_file": f"{part1_prefix}_output.txt",
                "api_usage": result["api_usage"],
            }
            with open(f"{part1_prefix}_metrics.json", "w") as f:
                json.dump(part1_metrics, f, indent=2)

            self.logger.info(f"Saved part 1 output/metrics to {part1_prefix}_*")

            part1_output = self.extract_text_output(result["stdout"])
            self.logger.info("Phase 3 iter 1 part 1 complete; running part 2 (LSP validation)...")

            part2_prompt = prompts.phase3_initial_part2(task, part1_output)

            # Save part 2 prompt alongside the part 1 prompt saved by ql_agent
            part2_prompt_path = os.path.join(cwd, f"{phase_name}_part2_prompt.txt")
            with open(part2_prompt_path, "w") as f:
                f.write(part2_prompt)
            self.logger.info(f"Saved part 2 prompt: {part2_prompt_path}")

            part2_result = await self._run_gemini(part2_prompt, env, cwd)

            # Save part 2 output, stderr, and metrics
            part2_prefix = os.path.join(cwd, f"{phase_name}_part2")

            with open(f"{part2_prefix}_output.txt", "w") as f:
                f.write(part2_result["stdout"])

            if part2_result["stderr"].strip():
                with open(f"{part2_prefix}_stderr.txt", "w") as f:
                    f.write(part2_result["stderr"])

            part2_metrics = {
                "phase_name": f"{phase_name}_part2",
                "success": part2_result["returncode"] == 0,
                "return_code": part2_result["returncode"],
                "character_count": len(part2_result["stdout"]),
                "stderr_characters": len(part2_result["stderr"]),
                "output_file": f"{part2_prefix}_output.txt",
                "api_usage": part2_result["api_usage"],
            }
            with open(f"{part2_prefix}_metrics.json", "w") as f:
                json.dump(part2_metrics, f, indent=2)

            self.logger.info(f"Saved part 2 output/metrics to {part2_prefix}_*")

            merged_usage = self._merge_api_usage(result["api_usage"], part2_result["api_usage"])
            return {
                "stdout": part2_result["stdout"],
                "stderr": result["stderr"] + part2_result["stderr"],
                "returncode": part2_result["returncode"],
                "api_usage": merged_usage,
            }

        return result

    # Prompt generation

    def create_phase1_prompt(self, task) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase1_no_tools(task)
        return prompts.phase1_full(task)

    def create_phase3_initial_prompt(self, task, use_cache: bool,
                                     collection_name: str, phase1_output: str = "") -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase3_no_tools(task, phase1_output)
        # Signal execute_prompt to run part 2 (LSP validation) after part 1 completes
        self._phase3_part2_task = task
        return prompts.phase3_full(task, use_cache, collection_name)

    def create_refinement_prompt(self, task, previous_feedback: str,
                                 iteration: int, collection_name: str) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.refinement_no_tools(task, previous_feedback, iteration)
        return prompts.refinement_full(task, previous_feedback, iteration, collection_name)

    # Workspace helpers

    def _setup_gemini_dir(self, output_dir: str):
        """Create .gemini/settings.json and copy system.md if available."""
        try:
            gemini_dir = os.path.join(output_dir, ".gemini")
            os.makedirs(gemini_dir, exist_ok=True)

            settings_path = os.path.join(gemini_dir, "settings.json")
            settings = {
                "model": {
                    "maxSessionTurns": 50,
                    "summarizeToolOutput": {
                        "run_shell_command": {
                            "tokenBudget": 1000
                        }
                    }
                }
            }
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
            self.logger.info(f"Created settings.json at {settings_path}")

            # Write policy file to deny rm commands
            policies_dir = os.path.join(gemini_dir, "policies")
            os.makedirs(policies_dir, exist_ok=True)
            policy_path = os.path.join(policies_dir, "deny-rm.toml")
            policy_content = (
                "[[rule]]\n"
                "toolName = \"run_shell_command\"\n"
                "commandPrefix = \"rm\"\n"
                "decision = \"deny\"\n"
                "priority = 100\n"
            )
            with open(policy_path, "w") as f:
                f.write(policy_content)
            self.logger.info(f"Created policy file at {policy_path}")

            # Resolve system.md: explicit env var, else repo-bundled gemini_system.md
            _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            _default_system_md = os.path.join(_repo_root, "gemini_system.md")
            system_md_src = os.environ.get("GEMINI_SYSTEM_MD_PATH", "") or _default_system_md
            if os.path.exists(system_md_src):
                dest = os.path.join(gemini_dir, "system.md")
                shutil.copy2(system_md_src, dest)
                self.logger.info(f"Copied system.md to {dest}")
            else:
                self.logger.info(f"system.md not found at {system_md_src}; skipping")

        except Exception as e:
            self.logger.error(f"Failed to setup .gemini directory: {e}")

    def _setup_project_scoped_codeql(self, workspace_dir: str):
        """Register project-scoped CodeQL MCP server."""
        original_cwd = os.getcwd()
        os.chdir(workspace_dir)
        try:
            self.logger.info("Setting up project-scoped CodeQL MCP server...")
            result = subprocess.run(
                [
                    "gemini", "mcp", "add", "codeql",
                    "--scope", "project",
                    "node", CODEQL_LSP_MCP_PATH + "/dist/index.js",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                self.logger.warning(f"CodeQL MCP setup warning: {result.stderr}")
            else:
                self.logger.info("CodeQL MCP configured")
        except Exception as e:
            self.logger.error(f"Failed to setup project-scoped CodeQL MCP: {e}")
        finally:
            os.chdir(original_cwd)

    def _setup_project_scoped_chroma(self, workspace_dir: str):
        """Register project-scoped Chroma MCP server (HTTP client)."""
        original_cwd = os.getcwd()
        os.chdir(workspace_dir)
        try:
            self.logger.info("Setting up project-scoped Chroma MCP server (HTTP client)...")
            result = subprocess.run(
                [
                    "gemini", "mcp", "add", "--scope", "project",
                    "chroma", "uvx", "--",
                    "chroma-mcp",
                    "--client-type", "http",
                    "--host", CHROMA_HOST,
                    "--port", str(CHROMA_PORT),
                    "--custom-auth-credentials", CHROMA_AUTH_TOKEN,
                    "--ssl", "false",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                self.logger.warning(f"Chroma MCP setup warning: {result.stderr}")
            else:
                self.logger.info("Chroma MCP configured (HTTP)")
        except Exception as e:
            self.logger.error(f"Failed to setup project-scoped Chroma MCP: {e}")
        finally:
            os.chdir(original_cwd)
