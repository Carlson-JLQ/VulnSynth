"""Agent backend abstraction for multi-CLI support.

Each backend encapsulates:
- CLI invocation (how to run the agent)
- Workspace setup (MCP config, settings files)
- Output parsing (token usage, cost)
- Tool name prefixes (for prompt generation)
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional
import logging


ABLATION_MODES = ("full", "no_tools", "no_lsp", "no_docs", "no_ast")


class AgentBackend(ABC):
    """Abstract base for agent CLI backends."""

    def __init__(self, model: str, logger: logging.Logger, ablation_mode: str = "full"):
        self.model = model
        self.logger = logger
        if ablation_mode not in ABLATION_MODES:
            raise ValueError(f"Unknown ablation_mode {ablation_mode!r}. Choose from {ABLATION_MODES}")
        self.ablation_mode = ablation_mode

    @abstractmethod
    async def execute_prompt(
        self,
        prompt: str,
        env: dict,
        cwd: str,
        phase_name: str,
    ) -> Dict:
        """Run a single prompt through the agent CLI.

        Returns dict with keys: stdout, stderr, returncode, api_usage
        """

    @abstractmethod
    def setup_workspace(self, output_dir: str, task) -> Optional[str]:
        """Prepare the workspace for this backend.

        MCP server config, config file generation,
        and any CLI-specific directory setup.

        Returns an optional config_path (e.g. for CLAUDE_DESKTOP_CONFIG).
        """

    @abstractmethod
    def get_tool_prefix(self) -> str:
        """Return the MCP tool name prefix used in prompts.

        Claude uses 'mcp__chroma__' and 'mcp__codeql__'.
        Gemini/Codex use '' 
        """

    @abstractmethod
    def parse_usage(self, stdout: str) -> Dict:
        """Parse token/cost metrics from CLI output."""

    @abstractmethod
    def create_refinement_prompt(self, task, previous_feedback: str,
                                 iteration: int, collection_name: str) -> str:
        """Create the prompt for query refinement (iteration 2+).

        Each backend may reference tools with different prefixes and use
        different prompt structures.
        """

    def get_phase3_prompts(self, task, config_path, output_dir, use_cache,
                           collection_name, iteration: int,
                           previous_feedback: Optional[str] = None) -> list:
        """Return a list of (prompt, phase_name) tuples for a phase 3 iteration.

        Most backends return a single prompt. Gemini returns two (step2 + step3)
        for iteration 1. Default implementation defers to shared prompts.
        """
        raise NotImplementedError("Subclass should override or use default flow")

    async def cleanup(self):
        """Best-effort cleanup of MCP server processes."""
        import asyncio

        patterns = [
            "chroma-mcp",
            "codeql-lsp-mcp/dist/index.js",
            "codeql.*language-server",
        ]

        async def _run_shell(cmd: str) -> tuple[int, str, str]:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            return (
                proc.returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )

        for pattern in patterns:
            try:
                await _run_shell(f"pkill -TERM -f '{pattern}' || true")
            except Exception:
                pass

        await asyncio.sleep(1.5)

        for pattern in patterns:
            try:
                rc, stdout, _ = await _run_shell(f"pgrep -af '{pattern}' || true")
                survivors = [line.strip() for line in stdout.splitlines() if line.strip()]
                if survivors:
                    self.logger.warning(
                        f"Cleanup survivors after TERM for pattern '{pattern}': "
                        + " | ".join(survivors[:10])
                    )
                    await _run_shell(f"pkill -KILL -f '{pattern}' || true")
            except Exception:
                pass

        await asyncio.sleep(0.5)

        zombie_check_cmd = (
            "ps -eo ppid,pid,stat,command | "
            "grep -E 'chroma-mcp|codeql-lsp-mcp/dist/index.js|codeql.*language-server' | "
            "grep -v grep || true"
        )
        try:
            _, stdout, _ = await _run_shell(zombie_check_cmd)
            lines = [line.strip() for line in stdout.splitlines() if line.strip()]
            if lines:
                self.logger.warning(
                    "Post-cleanup process snapshot (zombies with PPID=1 cannot be force-removed): "
                    + " | ".join(lines[:20])
                )
        except Exception:
            pass

        self.logger.info("MCP/LSP cleanup completed")


def create_backend(agent_type: str, model: str, logger: logging.Logger,
                   ablation_mode: str = "full", **backend_kwargs) -> AgentBackend:
    """Factory function to create the appropriate backend."""
    if agent_type == "claude":
        from .claude_backend import ClaudeBackend
        return ClaudeBackend(model, logger, ablation_mode=ablation_mode, **backend_kwargs)
    elif agent_type == "gemini":
        from .gemini_backend import GeminiBackend
        return GeminiBackend(model, logger, ablation_mode=ablation_mode)
    elif agent_type == "codex":
        from .codex_backend import CodexBackend
        return CodexBackend(model, logger, ablation_mode=ablation_mode, **backend_kwargs)
    else:
        raise ValueError(
            f"Unknown agent type: {agent_type!r}. Available: claude, gemini, codex"
        )
