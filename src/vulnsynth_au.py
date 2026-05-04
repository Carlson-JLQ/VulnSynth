#!/usr/bin/env python3

import asyncio
import json
import subprocess
import sys
import os
import tempfile
import re
import logging
import time
import shutil
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from pathlib import Path

import argparse
from datetime import datetime 
os.environ["ANONYMIZED_TELEMETRY"] = "false"
MODELS = {
    'sonnet-4': "claude-sonnet-4-20250514",
    'sonnet-4.5': "claude-sonnet-4-5-20250929"
}
class Vulnsynth_Agent_IterativeCLI:
    def __init__(self, agent_type: str, model: str, ablation_mode: str):
        self.agent_type = agent_type
        self.model = model
        self.ablation_mode = ablation_mode
        # Initialize agent and tools based on the specified type and ablation mode
        # For example, if agent_type is "claude", initialize a Claude agent
        
   
async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Vulnsynth Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--cve-id", required=True, help="CVE identifier")
    parser.add_argument("--vuln-db", help="Path to vulnerable CodeQL database")
    parser.add_argument("--fixed-db", help="Path to fixed CodeQL database")
    parser.add_argument("--diff", help="Path to fix commit diff file")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--max-iteration", default=10, type=int, help="Max iterations")
    parser.add_argument("--cache-phase-output", action="store_true", default=True)
    parser.add_argument("--no-cache-phase-output", dest="cache_phase_output", action="store_false")
    parser.add_argument("--model", default="sonnet-4",
                        choices=["sonnet-4", "sonnet-4.5", "gemini-2.5-pro", "gemini-2.5-flash","gpt-5","gpt-5.4"])
    parser.add_argument("--agent", default="claude", choices=["claude", "gemini", "codex"],
                        help="Agent backend to use")
    parser.add_argument("--ablation-mode", default="full",
                        choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"],
                        help="Ablation mode (default: full)")

    args = parser.parse_args()

    cli = Vulnsynth_Agent_IterativeCLI(agent_type=args.agent, model=args.model,
                              ablation_mode=args.ablation_mode)
    await cli.analyze_vulnerability(
        cve_id=args.cve_id,
        vuln_db=args.vuln_db,
        fixed_db=args.fixed_db,
        diff_file=args.diff,
        output_dir=args.output_dir,
        max_iteration=args.max_iteration,
        model=args.model
    )

if __name__ == "__main__":
    asyncio.run(main())