import asyncio
import json
import os
import re
import shutil
import signal
import sys
import time
import tomllib
from pathlib import Path
from typing import Dict, List, Optional

from . import AgentBackend
from . import codex_prompts as prompts

try:
    from ..config import (
        CHROMA_AUTH_TOKEN,
        CHROMA_DB_PATH,
        CHROMA_HOST,
        CHROMA_PORT,
        CODEQL_LSP_MCP_PATH,
    )
except Exception:
    try:
        from config import (
            CHROMA_AUTH_TOKEN,
            CHROMA_DB_PATH,
            CHROMA_HOST,
            CHROMA_PORT,
            CODEQL_LSP_MCP_PATH,
        )
    except Exception:
        CHROMA_HOST = os.environ.get("CHROMA_HOST", None)
        CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
        CHROMA_AUTH_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "test")
        CHROMA_DB_PATH = os.environ.get("CHROMA_DB_PATH", "")
        CODEQL_LSP_MCP_PATH = os.environ.get("CODEQL_LSP_MCP_PATH", "/path/to/codeql-lsp-mcp")

# Ablation modes that skip Chroma MCP setup
_NO_CHROMA_MODES = ("no_tools",)
# Ablation modes that skip CodeQL LSP MCP setup
_NO_LSP_MODES = ("no_tools",)

MODELS = {
    "gpt-5": "gpt-5",
}
_TRUTHY_VALUES = {"1", "true", "yes", "on"}


def _default_codex_config_path() -> str:
    home = os.environ.get("HOME", os.path.expanduser("~"))
    return os.path.join(home, ".codex", "config.toml")


def _find_adjacent_executable(name: str) -> Optional[str]:
    exe_dir = Path(sys.executable).resolve().parent
    candidate = exe_dir / name
    return str(candidate) if candidate.exists() else None


def _resolve_executable(name: str, env_var: str) -> Optional[str]:
    explicit = os.environ.get(env_var)
    if explicit and os.path.exists(explicit):
        return explicit
    discovered = shutil.which(name)
    if discovered:
        return discovered
    return _find_adjacent_executable(name)


def load_codex_cli_config(config_path: Optional[str] = None) -> dict:
    path = config_path or _default_codex_config_path()
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def get_local_codex_model(config_path: Optional[str] = None) -> Optional[str]:
    return load_codex_cli_config(config_path).get("model")


def _toml_literal(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def _jsonl_iter_bytes(byte_chunks: List[bytes]):
    """Buffer partial lines and yield complete JSONL lines."""
    buf = bytearray()
    for chunk in byte_chunks:
        if not chunk:
            continue
        buf.extend(chunk)
        while True:
            nl = buf.find(b"\n")
            if nl == -1:
                break
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            yield line
    if buf:
        yield bytes(buf)


def _parse_json_maybe(line) -> Optional[dict]:
    if isinstance(line, (bytes, bytearray)):
        s = line.decode("utf-8", errors="replace").strip()
    else:
        s = str(line).strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return {"_raw": s}


class CodexBackend(AgentBackend):

    def __init__(self, model: str, logger, ablation_mode: str = "full",
                 model_reasoning_effort: Optional[str] = None,
                 use_local_config: bool = False,
                 codex_config_path: Optional[str] = None):
        super().__init__(model, logger, ablation_mode=ablation_mode)
        self.cli_path = os.environ.get(
            "CODEX_PATH", shutil.which("codex") or "codex"
        )
        self.model_reasoning_effort = model_reasoning_effort
        self.codex_config_path = codex_config_path or _default_codex_config_path()
        env_prefers_local = os.environ.get("CODEX_USE_LOCAL_CONFIG", "").strip().lower()
        self.use_local_config = use_local_config or env_prefers_local in _TRUTHY_VALUES
        self.local_codex_config = load_codex_cli_config(self.codex_config_path)
        if self.use_local_config:
            configured_model = self.local_codex_config.get("model")
            if configured_model:
                self.model = configured_model

    def get_tool_prefix(self) -> str:
        return ""

    def get_codeql_tool_prefix(self) -> str:
        return ""

    @staticmethod
    def extract_text_output(stdout: str) -> str:
        """Extract assistant text from Codex JSONL output (agent_message frames)."""
        parts = []
        for line in stdout.splitlines():
            obj = _parse_json_maybe(line)
            if not obj or "_raw" in obj:
                continue
            # Format 1: {"msg": {"type": "agent_message", "message": "..."}}
            msg = obj.get("msg", {})
            if msg.get("type") == "agent_message":
                text = (msg.get("message", "") or "").strip()
                if text:
                    parts.append(text)
                continue
            # Format 2: {"type": "item.completed", "item": {"type": "agent_message", "text": "..."}}
            item = obj.get("item", {})
            if item.get("type") == "agent_message":
                text = (item.get("text", "") or "").strip()
                if text:
                    parts.append(text)
        result = "\n".join(parts)
        return result if result else stdout.strip()

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
            for line in stdout.splitlines():
                obj = _parse_json_maybe(line)
                if not obj or "_raw" in obj:
                    continue
                msg = obj.get("msg", {})
                if msg.get("type") == "token_count":
                    usage["sessions_count"] += 1
                    usage["total_input_tokens"] += int(msg.get("input_tokens", 0))
                    usage["total_output_tokens"] += int(msg.get("output_tokens", 0))
                    usage["total_reasoning_tokens"] += int(
                        msg.get("reasoning_output_tokens", 0)
                    )
            if usage["sessions_count"] > 0:
                self.logger.info(
                    f"Parsed Codex usage: {usage['sessions_count']} token_count frames, "
                    f"input={usage['total_input_tokens']}, "
                    f"output={usage['total_output_tokens']}, "
                    f"reasoning={usage['total_reasoning_tokens']}"
                )
            else:
                self.logger.warning("No Codex token_count frames found in output")
        except Exception as e:
            usage["parsing_errors"].append(f"Failed to parse Codex usage: {e}")
        return usage

    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Prepare Codex config while preserving local CLI settings."""
        if self.use_local_config:
            self.logger.info(
                f"Using local Codex CLI config at {self.codex_config_path}; "
                "skipping API-key login and CLI model override"
            )

        if self.ablation_mode in _NO_CHROMA_MODES:
            self.logger.info(f"Ablation mode '{self.ablation_mode}': skipping MCP setup")
            self._write_codex_config(include_chroma=False, include_codeql=False)
            return None

        include_codeql = self.ablation_mode not in _NO_LSP_MODES
        if not include_codeql:
            self.logger.info(
                f"Ablation mode '{self.ablation_mode}': skipping CodeQL LSP MCP setup"
            )

        self._write_codex_config(include_chroma=True, include_codeql=include_codeql)
        return None

    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        """Execute a single Codex context window via JSONL streaming."""
        api_key = env.get("OPENAI_API_KEY", "")
        if api_key and not self.use_local_config:
            try:
                login_proc = await asyncio.create_subprocess_exec(
                    self.cli_path, "login", "--with-api-key",
                    env=env,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await login_proc.communicate(input=api_key.encode())
            except Exception as e:
                self.logger.warning(f"Codex login failed: {e}")

        # Use "--dangerously-bypass.."" with caution.
        # You can also use --full-auto or configure
        # an appropriate sandbox policy for your environment.
        cmd = self._build_exec_command()

        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        usage_acc = {
            "sessions_count": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_reasoning_tokens": 0,
        }

        found_query_marker = False
        done_at: Optional[float] = None
        grace_after_done_sec = 6

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                start_new_session=True,
            )

            try:
                if proc.stdin:
                    proc.stdin.write(prompt.encode("utf-8"))
                    await proc.stdin.drain()
                    proc.stdin.close()
            except Exception:
                pass

            async def read_stdout():
                nonlocal found_query_marker, done_at
                assert proc.stdout is not None
                while True:
                    chunk = await proc.stdout.read(8192)
                    if not chunk:
                        break
                    stdout_chunks.append(chunk)
                    for raw_line in _jsonl_iter_bytes([chunk]):
                        obj = _parse_json_maybe(raw_line)
                        if not obj or "_raw" in obj:
                            continue
                        msg = obj.get("msg", {})
                        if msg.get("type") == "token_count":
                            usage_acc["sessions_count"] += 1
                            usage_acc["total_input_tokens"] += int(
                                msg.get("input_tokens", 0)
                            )
                            usage_acc["total_output_tokens"] += int(
                                msg.get("output_tokens", 0)
                            )
                            usage_acc["total_reasoning_tokens"] += int(
                                msg.get("reasoning_output_tokens", 0)
                            )
                        elif msg.get("type") == "agent_message":
                            text = msg.get("message", "") or ""
                            if re.search(r"QUERY_FILE_PATH:", text) and not found_query_marker:
                                found_query_marker = True
                                done_at = time.time()

            async def read_stderr():
                assert proc.stderr is not None
                while True:
                    chunk = await proc.stderr.read(8192)
                    if not chunk:
                        break
                    stderr_chunks.append(chunk)

            t_out = asyncio.create_task(read_stdout())
            t_err = asyncio.create_task(read_stderr())

            # Supervisor: wait for natural exit or query marker + grace period
            while True:
                if proc.returncode is not None:
                    break
                if found_query_marker:
                    if usage_acc["sessions_count"] > 0:
                        break
                    if done_at and (time.time() - done_at) >= grace_after_done_sec:
                        break
                await asyncio.sleep(0.05)

            # Graceful shutdown
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass

            await asyncio.gather(t_out, t_err, return_exceptions=True)

            stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")

            api_usage = {
                "total_cost_usd": 0.0,
                "total_input_tokens": usage_acc["total_input_tokens"],
                "total_cache_creation_tokens": 0,
                "total_cache_read_tokens": 0,
                "total_output_tokens": usage_acc["total_output_tokens"],
                "total_reasoning_tokens": usage_acc["total_reasoning_tokens"],
                "sessions_count": usage_acc["sessions_count"],
                "parsing_errors": [],
            }

            if usage_acc["sessions_count"] > 0:
                self.logger.info(
                    f"Codex usage: sessions={usage_acc['sessions_count']}, "
                    f"input={usage_acc['total_input_tokens']}, "
                    f"output={usage_acc['total_output_tokens']}, "
                    f"reasoning={usage_acc['total_reasoning_tokens']}"
                )
            else:
                self.logger.warning("No Codex token_count frames captured during execution")

            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": proc.returncode,
                "api_usage": api_usage,
            }

        except Exception as e:
            self.logger.error(f"Codex execution failed: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "api_usage": self.parse_usage(""),
            }

    # Prompt generation  

    def create_phase1_prompt(self, task) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase1_no_tools(task)
        return prompts.phase1_full(task)

    def create_phase3_initial_prompt(self, task, use_cache: bool,
                                     collection_name: str, phase1_output: str = "") -> str:
        if self.ablation_mode == "no_tools":
            return prompts.phase3_no_tools(task, phase1_output)
        return prompts.phase3_full(task, use_cache, collection_name)

    def create_refinement_prompt(self, task, previous_feedback: str,
                                 iteration: int, collection_name: str) -> str:
        if self.ablation_mode == "no_tools":
            return prompts.refinement_no_tools(task, previous_feedback, iteration)
        return prompts.refinement_full(task, previous_feedback, iteration, collection_name)

    # Workspace helpers

    def _build_exec_command(self) -> List[str]:
        model_id = MODELS.get(self.model, self.model)
        cmd = [
            self.cli_path, "exec",
            "--dangerously-bypass-approvals-and-sandbox",
            "--json",
        ]
        if not self.use_local_config:
            cmd.extend(["-m", model_id])
        return cmd

    def _write_codex_config(self, include_chroma: bool, include_codeql: bool):
        """Write ~/.codex/config.toml with the appropriate MCP servers."""
        config_path = self.codex_config_path
        codex_dir = os.path.dirname(config_path)
        os.makedirs(codex_dir, exist_ok=True)

        try:
            existing = load_codex_cli_config(config_path)
        except Exception as e:
            self.logger.warning(f"Could not read existing config.toml: {e}")
            existing = {}

        if self.use_local_config:
            model_reasoning_effort = (
                existing.get("model_reasoning_effort")
                or self.model_reasoning_effort
                or "medium"
            )
        else:
            model_reasoning_effort = (
                self.model_reasoning_effort
                or existing.get("model_reasoning_effort")
                or "medium"
            )

        lines = []
        if existing.get("model"):
            lines.append(f'model = {_toml_literal(existing["model"])}')
        lines.append(f'model_reasoning_effort = {_toml_literal(model_reasoning_effort)}')

        windows = existing.get("windows", {})
        if windows:
            lines.extend(["", "[windows]"])
            for key, value in windows.items():
                lines.append(f"{key} = {_toml_literal(value)}")

        projects = existing.get("projects", {})
        for project_path, settings in projects.items():
            lines.extend(["", f"[projects.{_toml_literal(project_path)}]"])
            for key, value in settings.items():
                lines.append(f"{key} = {_toml_literal(value)}")

        if include_chroma:
            chroma_mcp_command = _resolve_executable("chroma-mcp", "CHROMA_MCP_PATH")
            uvx_command = _resolve_executable("uvx", "UVX_PATH")
            lines.extend(["", "[mcp_servers.chroma]"])
            chroma_args: List[str]
            if chroma_mcp_command:
                lines.append(f'command = "{chroma_mcp_command}"')
                if CHROMA_HOST:
                    chroma_args = [
                        "--client-type", "http",
                        "--host", CHROMA_HOST,
                        "--port", str(CHROMA_PORT),
                        "--custom-auth-credentials", CHROMA_AUTH_TOKEN,
                        "--ssl", "false",
                    ]
                else:
                    chroma_args = [
                        "--client-type", "persistent",
                        "--data-dir", CHROMA_DB_PATH,
                    ]
            elif uvx_command:
                lines.append(f'command = "{uvx_command}"')
                chroma_args = ["chroma-mcp"]
                if CHROMA_HOST:
                    chroma_args.extend(
                        [
                            "--client-type", "http",
                            "--host", CHROMA_HOST,
                            "--port", str(CHROMA_PORT),
                            "--custom-auth-credentials", CHROMA_AUTH_TOKEN,
                            "--ssl", "false",
                        ]
                    )
                else:
                    chroma_args.extend(
                        [
                            "--client-type", "persistent",
                            "--data-dir", CHROMA_DB_PATH,
                        ]
                    )
            else:
                raise RuntimeError(
                    "Chroma MCP requested, but neither 'chroma-mcp' nor 'uvx' is available. "
                    "Install chroma-mcp/uvx or set CHROMA_MCP_PATH/UVX_PATH."
                )
            args_toml = ", ".join(f'"{a}"' for a in chroma_args)
            lines.append(f"args = [{args_toml}]")

        if include_codeql:
            lines.extend(["", "[mcp_servers.codeql]"])
            lines.append('command = "node"')
            lines.append(f'args = ["{CODEQL_LSP_MCP_PATH}/dist/index.js"]')

        content = "\n".join(line for line in lines if line is not None).strip() + "\n"
        with open(config_path, "w") as f:
            f.write(content)
        self.logger.info(
            f"Wrote Codex config to {config_path} "
            f"(chroma={include_chroma}, codeql={include_codeql})"
        )
