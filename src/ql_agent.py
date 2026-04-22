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
try:
    from .utils import save_output_to_chroma, extract_phase1_sections
    from .data_types import VulnAnalysisTask
    from .diff_preprocessing import preprocess_diff_for_prompt
    from config import AST_CACHE, NVD_CACHE, CHROMA_DB_PATH, CODEQL_LSP_MCP_PATH, QL_CODER_ROOT_DIR, CVES_PATH, CVE_DESCRIPTIONS_FILE
    from .agent_backends import create_backend
except ImportError:
    from utils import save_output_to_chroma, extract_phase1_sections
    from data_types import VulnAnalysisTask, IterationResult
    from diff_preprocessing import preprocess_diff_for_prompt
    from ast_extraction import run_phase2
    from agent_backends import create_backend
    from config import AST_CACHE, NVD_CACHE, CHROMA_DB_PATH, CODEQL_LSP_MCP_PATH, QL_CODER_ROOT_DIR, CVES_PATH, CVE_DESCRIPTIONS_FILE
    from query_subagents_evaluation import run_query_with_evaluation_results, compile_query_once

class QLAgentIterative:

    def __init__(self, working_dir: str = None, agent_type: str = "claude", model: str = "sonnet-4",
                 ablation_mode: str = "full", codex_use_local_config: bool = False,
                 claude_use_local_config: bool = False):
        if working_dir:
            self.working_dir = working_dir
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.working_dir = os.path.dirname(script_dir)

        self.temp_dir = None
        self.chroma_db_path = CHROMA_DB_PATH
        self.logger = logging.getLogger(__name__)
        backend_kwargs = {}
        if agent_type == "codex":
            backend_kwargs["use_local_config"] = codex_use_local_config
        if agent_type == "claude":
            backend_kwargs["use_local_config"] = claude_use_local_config
        self.backend = create_backend(
            agent_type,
            model,
            self.logger,
            ablation_mode=ablation_mode,
            **backend_kwargs,
        )
        self.iteration_results = []

    def setup_logging(self, output_dir: str):
        """Setup detailed logging for debugging"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(output_dir, f"iterative_vuln_analysis_{timestamp}.log")

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Log file: {log_file}")
    
    def setup_chroma_db(self):
        """Setup ChromaDB using existing shared database path"""
        self.chroma_db_path = CHROMA_DB_PATH 
        self.logger.info(f"Using ChromaDB: {self.chroma_db_path}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_id = f"{os.getpid()}_{timestamp}"
        self.created_collections = []
        
        return self.chroma_db_path

    async def cleanup_mcp_servers(self):
        """Kill all MCP language servers"""
        try:
            self.logger.info("Cleaning up MCP servers...")
            
            # Kill chroma-mcp processes
            chroma_cmd = "pkill -f 'chroma-mcp'"
            chroma_result = await asyncio.create_subprocess_shell(
                chroma_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await chroma_result.communicate()
            
            # Kill codeql-mcp processes
            codeql_mcp_cmd = f"pkill -f '{CODEQL_LSP_MCP_PATH}/dist/index.js'"
            codeql_mcp_result = await asyncio.create_subprocess_shell(
                codeql_mcp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await codeql_mcp_result.communicate()
            
            # Kill CodeQL language server processes
            codeql_ls_cmd = "pkill -f 'codeql.*language-server'"
            codeql_ls_result = await asyncio.create_subprocess_shell(
                codeql_ls_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await codeql_ls_result.communicate()
            
            self.logger.info("MCP servers cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Error during MCP server cleanup: {e}") 

    async def run_iterative_analysis(self, task: VulnAnalysisTask, use_cache: bool = True) -> Dict:
        """Run iterative analysis with context windows and automated testing"""
        
        start_time = datetime.now()
        self.setup_chroma_db()
        
        # Setup output directory
        output_base = os.path.join(self.working_dir, task.output_dir)
        os.makedirs(output_base, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dir_name = f"ql_agent_{task.cve_id or 'unknown'}_{timestamp}_{task.max_iteration}-iterations_{task.model}_{self.backend.ablation_mode}"
        self.temp_dir = os.path.join(output_base, dir_name)
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Create collection name for ChromaDB if caching is enabled
        collection_name = None
        if use_cache:
            cve_id = getattr(task, 'cve_id', None) or 'unknown'
            collection_name = f"cve_analysis_{cve_id.lower().replace('-', '_')}_{self.run_id}"
            self.collection_name = collection_name
        
        try:
            self.logger.info(f"Starting iterative analysis for {task.cve_id}")
            self.logger.info(f"Max iterations: {task.max_iteration}")
             
            output_dir = os.path.join(self.temp_dir, "results")
            self.output_dir = output_dir
            os.makedirs(output_dir, exist_ok=True)
            self.setup_logging(output_dir)

            # Update task with the actual working directory that will be used
            task.working_dir = os.path.abspath(output_dir)
            qlpack_source = os.path.join(QL_CODER_ROOT_DIR, "qlpack.yml")
            qlpack_dest = os.path.join(output_dir, "qlpack.yml")
            shutil.copy2(qlpack_source, qlpack_dest)
            self.logger.info(f"Copied qlpack.yml to {qlpack_dest}") 
            # agent backend specific workspace setup (MCP config, project scoped servers) 
            config_path = self.backend.setup_workspace(output_dir, task)
            # Phase 1 & 2: Run once (context setup)
            self.logger.info("Running Phase 1 & 2 (one-time setup)")
            phase1_result, phase2_result = await self._run_setup_phases(
                task, config_path, output_dir, use_cache, collection_name
            )
            
            if not phase1_result["success"] or not phase2_result["success"]:
                return {"success": False, "error": "Setup phases failed"}
            
            # Phase 3: Iterative query refinement
            self.logger.info("Starting iterative Phase 3")
            phase1_text = self.backend.extract_text_output(phase1_result.get("output", "")) \
                if hasattr(self.backend, "extract_text_output") else phase1_result.get("output", "")

            if self.backend.ablation_mode == "no_tools":
                sections = extract_phase1_sections(phase1_text)
                phase1_output = "\n\n".join(v for v in sections.values() if v)
                json_path = os.path.join(output_dir, f"phase1_extracted_sections_{task.cve_id}.json")
                with open(json_path, "w") as f:
                    json.dump(sections, f, indent=2)
                self.logger.info(f"Saved extracted sections to: {json_path}")
            else:
                phase1_output = phase1_text

            final_result = await self._run_iterative_phase3(
                task, config_path, output_dir, use_cache, collection_name,
                phase1_output=phase1_output
            )
            
            # Combine results
            result = {
                "success": final_result["success"],
                "analysis_dir": self.temp_dir,
                "output_dir": output_dir,
                "phase1_output": phase1_result["output"],
                "phase2_output": phase2_result["output"],
                "phase3_iterations": self.iteration_results,
                "final_query": final_result.get("final_query"),
                "total_iterations": len(self.iteration_results),
                "error": final_result.get("error")
            }
            
            # Generate comprehensive cost summary with real API usage data
            self._create_cost_usage_summary(output_dir, task.cve_id)
            
            # Save metadata
            end_time = datetime.now()
            self._save_metadata(task, result, start_time, end_time, use_cache, collection_name)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Iterative analysis failed: {e}")
            return {"success": False, "error": str(e), "analysis_dir": self.temp_dir}
        finally:
            await self.cleanup_mcp_servers()
    
    async def _run_setup_phases(self, task: VulnAnalysisTask, config_path: str,
                               output_dir: str, use_cache: bool, collection_name: str) -> tuple:
        """Run Phase 1 and 2 once to establish context"""
        ablation = self.backend.ablation_mode

        # Phase 1: Identify security components
        phase1_prompt = self.backend.create_phase1_prompt(task)
        phase1_result = await self._execute_single_context_window(
            config_path, phase1_prompt, output_dir, task, 1, "phase1"
        )

        if ablation not in ("no_tools") and use_cache and phase1_result["success"]:
            save_output_to_chroma(phase1_result, 1, task, self.temp_dir, self.logger, collection_name)

        # Phase 2: Extract AST — skip for no_tools and no_ast modes
        if ablation in ("no_tools", "no_ast"):
            self.logger.info(f"Ablation mode '{ablation}': skipping Phase 2 (AST extraction)")
            phase2_result = {"success": True, "output": ""}
        else:
            phase2_result = await run_phase2(self, task, output_dir)
            if use_cache and phase2_result["success"]:
                save_output_to_chroma(phase2_result, 2, task, self.temp_dir, self.logger, collection_name)

        return phase1_result, phase2_result
    
    async def _run_iterative_phase3(self, task: VulnAnalysisTask, config_path: str,
                                   output_dir: str, use_cache: bool, collection_name: str,
                                   phase1_output: str = "") -> Dict:
        """Run Phase 3 with iterative context windows"""

        previous_feedback = None

        for iteration in range(1, task.max_iteration + 1):
            self.logger.info(f"Starting iteration {iteration}/{task.max_iteration}")

            # Create iteration-specific prompt
            if iteration == 1:
                prompt = self.backend.create_phase3_initial_prompt(
                    task, use_cache=use_cache, collection_name=collection_name,
                    phase1_output=phase1_output
                )
            else:
                # Refinement prompt with previous feedback
                self.logger.info(f"Creating refinement prompt for iteration {iteration} with feedback: {len(previous_feedback) if previous_feedback else 0} chars")
                prompt = self._create_refinement_prompt(task, previous_feedback, iteration, collection_name)
            
            # Execute context window
            self.logger.info(f"Executing Phase 3 iteration {iteration} context window...")
            result = await self._execute_single_context_window(
                config_path, prompt, output_dir, task, 3, f"phase3_iter_{iteration}"
            )
            
            # Debug the result
            self.logger.info(f"Context window result: success={result.get('success')}, output_length={len(result.get('output', ''))}")
            if not result.get('success'):
                self.logger.error(f"Context window failed: {result.get('error', 'Unknown error')}")
            
            # Extract query and test it
            iteration_result = await self._test_iteration_query(
                result, task, output_dir, iteration
            )
            
            self.iteration_results.append(iteration_result)
            
            # Check if we have a successful query
            if self._is_iteration_successful(iteration_result):
                self.logger.info(f"Successful query found in iteration {iteration}")
                return {
                    "success": True,
                    "final_query": iteration_result.query_path,
                    "iterations_used": iteration
                }
            
            # Prepare feedback for next iteration
            previous_feedback = self._generate_feedback(iteration_result, task)
            self.logger.info(f"Generated feedback for iteration {iteration}: {len(previous_feedback) if previous_feedback else 0} chars")
            
            # Save iteration feedback to results directory (output_dir is already results)
            os.makedirs(output_dir, exist_ok=True)
            feedback_path = os.path.join(output_dir, f"feedback_iter_{iteration}.txt")
            with open(feedback_path, 'w') as f:
                f.write(previous_feedback or "No feedback generated")
            self.logger.info(f"Saved iteration {iteration} feedback: {feedback_path}")
            
            # Log iteration summary
            self.logger.info(f"Iteration {iteration} summary: {previous_feedback[:200]}...")
        
        # Max iterations reached
        self.logger.warning(f"Max iterations ({task.max_iteration}) reached without success")
        return {
            "success": False,
            "error": f"Max iterations ({task.max_iteration}) reached",
            "iterations_used": task.max_iteration
        }
    
    async def _execute_single_context_window(self, config_path: str, prompt: str,
                                           output_dir: str, task: VulnAnalysisTask,
                                           phase_num: int, phase_name: str) -> Dict:
        """Execute a single context window (up to 50 turns)"""
        
        # Create prompt file
        prompt_path = os.path.join(output_dir, f"{phase_name}_prompt.txt")
        with open(prompt_path, 'w') as f:
            f.write(prompt)
        
        # Prepare environment
        env = os.environ.copy()
        env["CHROMA_DATA_DIR"] = os.path.abspath(self.chroma_db_path)
        
        if task.vuln_db_path:
            env["VULN_CODEQL_DB"] = os.path.abspath(task.vuln_db_path)
        if task.fixed_db_path:
            env["FIXED_CODEQL_DB"] = os.path.abspath(task.fixed_db_path)

        result = await self.backend.execute_prompt(prompt, env, output_dir, phase_name)  
        stdout_str = result["stdout"]
        stderr_str = result["stderr"]
        api_usage = result.get("api_usage", {})
        
        # Save ALL outputs with detailed metrics
        output_path = os.path.join(output_dir, f"{phase_name}_output.txt")
        with open(output_path, 'w') as f:
            f.write(stdout_str)
        
        # Save stderr if it contains useful info
        if stderr_str.strip():
            stderr_path = os.path.join(output_dir, f"{phase_name}_stderr.txt")
            with open(stderr_path, 'w') as f:
                f.write(stderr_str)
         
        # Save detailed metrics
        success = result["returncode"] == 0 
        metrics = {
            "phase_name": phase_name,
            "success": success,
            "return_code": result['returncode'],
            "character_count": len(stdout_str),
            "stderr_characters": len(stderr_str),
            "output_file": output_path,
            "timestamp": datetime.now().isoformat(),
            "api_usage": api_usage
        }
        
        metrics_path = os.path.join(output_dir, f"{phase_name}_metrics.json")
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        
        return {
            "success": success,
            "output": stdout_str,
            "stderr": stderr_str,
            "context_length": len(stdout_str),
            "metrics_file": metrics_path
        }
              
    async def _test_iteration_query(self, context_result: Dict, task: VulnAnalysisTask,
                                   output_dir: str, iteration: int) -> IterationResult:
        """Extract query from context and test it automatically"""
        
        iteration_result = IterationResult(
            iteration_number=iteration,
            context_length=context_result.get("context_length", 0)
        )
        
        if not context_result["success"]:
            iteration_result.error = context_result.get("error", "Context execution failed")
            return iteration_result
        
        # Look for query file path in output
        context_output = context_result.get("output", "")
        self.logger.info(f"Looking for QUERY_FILE_PATH marker in output")
        
        query_path = None
        # Look for the QUERY_FILE_PATH marker
        import re
        path_match = re.search(r'QUERY_FILE_PATH:\s*([^\s\"}*\n\r]+)', context_output)
        if path_match:
            file_path = path_match.group(1).strip('*')  # Strip any trailing asterisks
            self.logger.info(f"Found query file path: {file_path}")
            
            # Move file to output directory if needed (output_dir is already results)
            os.makedirs(output_dir, exist_ok=True)
            
            # Try multiple locations for the file
            filename = os.path.basename(file_path) if os.path.sep in file_path else file_path
            possible_locations = [
                file_path,  # Exact path provided (might be absolute)
                os.path.join(".", filename),  # Current directory
                os.path.join(output_dir, filename),  # Output directory (results)
            ]
            
            self.logger.info(f"Searching for file in {len(possible_locations)} locations:")
            for i, loc in enumerate(possible_locations):
                self.logger.info(f"  {i+1}. {loc} (exists: {os.path.exists(loc)})")
            
            found_file = None
            for location in possible_locations:
                if os.path.exists(location):
                    found_file = location
                    self.logger.info(f"Found file at: {location}")
                    break
            
            if found_file:
                # Use the file where it was found (no moving needed)
                query_path = found_file
                self.logger.info(f"Found query file: {query_path}")
            else:
                # Search more broadly for any .ql files with CVE ID
                self.logger.warning(f"Query file not found at any expected location")
                # Try to find any .ql file in current or output directories
                for search_dir in [".", output_dir]:
                    if os.path.exists(search_dir):
                        ql_files = [f for f in os.listdir(search_dir) if f.endswith('.ql') and task.cve_id.replace('-', '_').lower() in f.lower()]
                        if ql_files:
                            query_path = os.path.join(search_dir, ql_files[0])
                            self.logger.info(f"Found alternate query file: {query_path}")
                            break
        
        if not query_path:
            if path_match:
                self.logger.warning(f"QUERY_FILE_PATH found but file not located: {file_path}")
            else:
                self.logger.warning(f"No QUERY_FILE_PATH marker found in output")
            
            # Fallback: search for expected filename pattern CVE-xxxx-xxxx-query-iter-N.ql
            self.logger.info(f"Searching for expected query filename pattern: {task.cve_id}-query-iter-{iteration}.ql")
            expected_filename = f"{task.cve_id}-query-iter-{iteration}.ql"
            
            # Try to find the expected filename in current or output directories
            for search_dir in [".", output_dir]:
                if os.path.exists(search_dir):
                    expected_path = os.path.join(search_dir, expected_filename)
                    if os.path.exists(expected_path):
                        query_path = expected_path
                        self.logger.info(f"Found expected query file: {query_path}")
                        break
                    
                    # Also search for any .ql files with CVE ID and iteration number
                    pattern = f"{task.cve_id}-query-iter-{iteration}.ql"
                    ql_files = [f for f in os.listdir(search_dir) if f == pattern]
                    if ql_files:
                        query_path = os.path.join(search_dir, ql_files[0])
                        self.logger.info(f"Found matching query file: {query_path}")
                        break
            
            if not query_path:
                error_msg = f"Query file not found. Expected: {expected_filename}"
                if path_match:
                    error_msg += f" (QUERY_FILE_PATH pointed to: {file_path})"
                iteration_result.error = error_msg
                return iteration_result
        
        self.logger.info(f"Extracted query: {query_path}")
        
        iteration_result.query_path = query_path
        
        # Update metrics file with query information
        self._update_metrics_with_query(output_dir, iteration, query_path)
        
        try:
            # Test compilation and save output
            compilation_summary = await compile_query_once(query_path, self.logger)
            iteration_result.compilation_summary = compilation_summary
            
            # Save compilation results
            compilation_path = os.path.join(output_dir, f"compilation_iter_{iteration}.txt")
            with open(compilation_path, 'w') as f:
                f.write(compilation_summary)
            self.logger.info(f"Saved compilation results: {compilation_path}")
            
            # If compilation successful, run on databases
            if "COMPILATION SUCCESS" in compilation_summary:
                iteration_result.compilation_successful = True
                
                execution_summary, vuln_eval, fixed_eval, execution_successful = await run_query_with_evaluation_results(
                    query_path=query_path,
                    vuln_db_path=task.vuln_db_path,
                    fixed_db_path=task.fixed_db_path,
                    cve_id=task.cve_id,
                    iteration_number=iteration,
                    output_dir=output_dir,
                    logger=self.logger
                )
                iteration_result.execution_summary = execution_summary
                iteration_result.vulnerable_results = vuln_eval.num_results if vuln_eval else 0
                iteration_result.fixed_results = fixed_eval.num_results if fixed_eval else 0
                iteration_result.success = execution_successful
                iteration_result.vuln_recall_method = vuln_eval.recall_method if vuln_eval else False
                iteration_result.fixed_recall_method = fixed_eval.recall_method if fixed_eval else False
                iteration_result.vuln_tp_methods = vuln_eval.num_tp_methods if vuln_eval else 0
                iteration_result.fixed_tp_methods = fixed_eval.num_tp_methods if fixed_eval else 0
                iteration_result.vuln_num_results = vuln_eval.num_results if vuln_eval else 0
                iteration_result.fixed_num_results = fixed_eval.num_results if fixed_eval else 0
                iteration_result.vuln_eval_result = vuln_eval if vuln_eval else None
                iteration_result.fixed_eval_result = fixed_eval if fixed_eval else None
                
                # Save execution results 
                execution_path = os.path.join(output_dir, f"execution_iter_{iteration}.txt")
                with open(execution_path, 'w') as f:
                    f.write(execution_summary)
                self.logger.info(f"Saved execution results: {execution_path}") 
 
            else:
                iteration_result.error = "Compilation failed"
            
        except Exception as e:
            iteration_result.error = f"Testing failed: {str(e)}"
        
        return iteration_result
    
    def _is_iteration_successful(self, iteration_result: IterationResult) -> bool:
        """Determine if iteration was successful based on method hit counts"""
        # Success criteria: Query compiled and either:
        # 1) Hit vulnerable methods but fewer hits on fixed methods, OR
        # 2) Query hits targets and vulnerable has more total results than fixed
        
        if not iteration_result.compilation_successful:
            success_reason = "Query compilation failed"
            success = False
        elif iteration_result.vuln_tp_methods <= 0:
            success_reason = "No target methods hit in vulnerable version"
            success = False
        else:
            if iteration_result.fixed_recall_method == False and iteration_result.vuln_tp_methods > 0:
                success_reason = "Vulnerable TP Method Hit > 0 and Fixed Recall Method = false" 
                success = True
            else:
                success_reason = "Neither success condition met"
                success = False
        # Debug logging
        self.logger.info(f"Success check - Compilation: {iteration_result.compilation_successful}, "
                        f"Vuln recall: {iteration_result.vuln_recall_method}, "
                        f"Fixed recall: {iteration_result.fixed_recall_method}, "
                        f"Vuln TP methods: {iteration_result.vuln_tp_methods}, "
                        f"Fixed TP methods: {iteration_result.fixed_tp_methods}, "
                        f"Vuln results: {iteration_result.vuln_num_results}, "
                        f"Fixed results: {iteration_result.fixed_num_results}")
        self.logger.info(f"{success_reason}")
        
        return success
    
    def _generate_feedback(self, iteration_result: IterationResult, task: VulnAnalysisTask) -> str:
        """Generate concise feedback for next iteration"""
        
        feedback = [f"## Iteration {iteration_result.iteration_number} Results"]
        
        # Always include the previous query contents for reference
        if iteration_result.query_path and os.path.exists(iteration_result.query_path):
            try:
                with open(iteration_result.query_path, 'r') as f:
                    query_contents = f.read()
                feedback.append(f"\n## Previous Query (Iteration {iteration_result.iteration_number})")
                feedback.append("```ql")
                feedback.append(query_contents)
                feedback.append("```")
            except Exception as e:
                feedback.append(f"\nCould not read previous query: {e}")
        
        # Handle different error/result scenarios
        if iteration_result.error:
            feedback.append(f"\nError in iteration {iteration_result.iteration_number}: {iteration_result.error}")
            
            # Still include compilation details if available (for compilation failures)
            if iteration_result.compilation_summary:
                feedback.append("\n## Compilation Details")
                feedback.append(iteration_result.compilation_summary)
                
            # Still include execution details if available  
            if iteration_result.execution_summary:
                feedback.append("\n## Execution Details")
                feedback.append(iteration_result.execution_summary)
        
        elif not iteration_result.compilation_summary:
            feedback.append(f"\nNo compilation attempted in iteration {iteration_result.iteration_number}")
        
        else:
            # Normal case - include compilation and execution summaries
            feedback.append("\n## Compilation Results")
            feedback.append(iteration_result.compilation_summary)
            
            if iteration_result.execution_summary:
                feedback.append("\n## Execution Results")
                feedback.append(iteration_result.execution_summary)
        
        # Add detailed evaluation-based feedback with SARIF analysis
        if iteration_result.compilation_successful and iteration_result.vuln_eval_result is not None:
            feedback.append("\n## Detailed Evaluation Analysis")
            
            vuln_eval = iteration_result.vuln_eval_result
            fixed_eval = iteration_result.fixed_eval_result
            
            # Coverage summary
            total_methods = vuln_eval.total_fixed_methods
            hit_methods = vuln_eval.num_tp_methods
            total_files = vuln_eval.total_fixed_files
            hit_files = vuln_eval.num_tp_files
            
            # Calculate accurate coverage based on target methods actually hit
            target_methods_set = set(vuln_eval.fixed_methods)
            hit_methods_set = set(vuln_eval.hit_methods)
            successfully_targeted_count = len(target_methods_set.intersection(hit_methods_set))
            
            target_files_set = set(vuln_eval.fixed_files)  
            hit_files_set = set(vuln_eval.hit_files)
            successfully_targeted_files_count = len(target_files_set.intersection(hit_files_set))
            
            feedback.append(f"\n**Method Coverage**: {successfully_targeted_count}/{total_methods} target methods")
            feedback.append(f"**File Coverage**: {successfully_targeted_files_count}/{total_files} target files")
     
            # Show target files that were successfully hit (intersection only)
            target_files_hit = list(target_files_set.intersection(hit_files_set))
            if target_files_hit:
                feedback.append("\n**Successfully targeted files**:")
                for file_path in target_files_hit[:3]:
                    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                    feedback.append(f"   - {file_name}")
                if len(target_files_hit) > 3:
                    feedback.append(f"   ... and {len(target_files_hit) - 3} more")
            
            # Show files that were missed
            if vuln_eval.missed_files:
                feedback.append("\n**Missed target files**:")
                for file_path in vuln_eval.missed_files[:3]:
                    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                    feedback.append(f"   - {file_name}")
                if len(vuln_eval.missed_files) > 3:
                    feedback.append(f"   ... and {len(vuln_eval.missed_files) - 3} more")
     
            # Show target methods that were successfully hit (intersection of hit_methods with fixed_methods)
            target_methods_set = set(vuln_eval.fixed_methods)
            hit_methods_set = set(vuln_eval.hit_methods)
            successfully_targeted = list(target_methods_set.intersection(hit_methods_set))
            
            if successfully_targeted:
                feedback.append("\n**Successfully targeted methods**:")
                for method in successfully_targeted[:5]:
                    method_name = method.split(':')[-1]
                    feedback.append(f"   - {method_name}")
                if len(successfully_targeted) > 5:
                    feedback.append(f"   ... and {len(successfully_targeted) - 5} more")
 
            
            # Show methods that were missed
            if vuln_eval.missed_methods:
                feedback.append("\n**Missed target methods (focus on these)**:")
                for method in vuln_eval.missed_methods[:5]:
                    method_name = method.split(':')[-1]
                    feedback.append(f"   - {method_name}")
                if len(vuln_eval.missed_methods) > 5:
                    feedback.append(f"   ... and {len(vuln_eval.missed_methods) - 5} more")
            
            # Show false positives in fixed version (target methods hit in fixed version)
            if fixed_eval and fixed_eval.hit_methods:
                # False positives are TARGET methods that are still hit in the fixed version
                target_methods_set = set(vuln_eval.fixed_methods)
                fixed_hit_methods_set = set(fixed_eval.hit_methods)
                false_positives = list(target_methods_set.intersection(fixed_hit_methods_set))
                
                if false_positives:
                    feedback.append("\n**False positives (hit in fixed version)**:")
                    for method in false_positives[:5]:
                        method_name = method.split(':')[-1]
                        feedback.append(f"   - {method_name}")
                    if len(false_positives) > 5:
                        feedback.append(f"   ... and {len(false_positives) - 5} more")
            
            # Evaluation summary  
            feedback.append(f"\n**Evaluation Summary**:")
            feedback.append(f"- Vulnerable DB File Recall: {vuln_eval.recall_file}")
            feedback.append(f"- Fixed DB File Recall: {fixed_eval.recall_file if fixed_eval else False}")
            feedback.append(f"- Vulnerable DB Method Recall: {vuln_eval.recall_method}")
            feedback.append(f"- Fixed DB Method Recall: {fixed_eval.recall_method if fixed_eval else False}")
            feedback.append(f"- Total Query Results: Vulnerable={vuln_eval.num_results}, Fixed={fixed_eval.num_results if fixed_eval else 0}")
            feedback.append(f"- Code Flow Paths: Vulnerable={vuln_eval.num_paths}, Fixed={fixed_eval.num_paths if fixed_eval else 0}")
        
        feedback.append("\n## Next Steps")
        feedback.append("We want vulnerable DB method recall and we don't want fixed DB method recall!")
        if not iteration_result.compilation_successful:
            feedback.append("**Priority**: Fix compilation errors in the query.")
        elif iteration_result.compilation_successful and iteration_result.vuln_eval_result:
            # Use file and method level information for better guidance
            vuln_eval = iteration_result.vuln_eval_result
            fixed_eval = iteration_result.fixed_eval_result
            
            if not vuln_eval.recall_file:
                feedback.append("**Priority**: Improve file targeting - query is not hitting any target files. Focus on the missed files listed above.")
            elif vuln_eval.recall_file and not vuln_eval.recall_method:
                feedback.append("**Priority**: Improve method targeting - query hits target files but misses methods. Focus on the missed methods listed above.")
            elif fixed_eval and fixed_eval.recall_method:
                feedback.append("**Priority**: Reduce false positives by adding more specific conditions to avoid hitting the methods listed above.")
            elif len(vuln_eval.hit_methods) < vuln_eval.total_fixed_methods:
                feedback.append("**Priority**: Expand coverage to hit more of the missed vulnerable methods.")
            else:
                feedback.append("**Success**: Query successfully targets all vulnerable methods without false positives.")
        else:
            feedback.append("**Priority**: Improve targeting to hit the actual vulnerable methods.")
        
        return "\n".join(feedback) 
    
    def _update_metrics_with_query(self, output_dir: str, iteration: int, query_path: str):
        """Update the phase 3 iteration metrics file with query information"""
        try:
            metrics_file = os.path.join(output_dir, f"phase3_iter_{iteration}_metrics.json")
            if os.path.exists(metrics_file):
                with open(metrics_file, 'r') as f:
                    metrics = json.load(f)
                
                # Add query information
                metrics["query_file_path"] = query_path
                metrics["query_filename"] = os.path.basename(query_path) if query_path else None
                metrics["query_extracted"] = bool(query_path)
                
                # Save updated metrics
                with open(metrics_file, 'w') as f:
                    json.dump(metrics, f, indent=2)
                
                self.logger.info(f"Updated metrics with query info: {metrics_file}")
        except Exception as e:
            self.logger.warning(f"Failed to update metrics with query info: {e}")
    
    def _create_cost_usage_summary(self, output_dir: str, cve_id: str):
        """Create comprehensive token usage and cost summary from actual API data"""
        try:
            summary_path = os.path.join(output_dir, "token_usage_summary.txt")
            
            # Collect all API usage data from metrics files
            phase1_usage = None
            phase2_usage = None
            phase3_iterations = []
            
            # Parse Phase 1 metrics
            phase1_metrics_path = os.path.join(output_dir, "phase1_metrics.json")
            if os.path.exists(phase1_metrics_path):
                with open(phase1_metrics_path, 'r') as f:
                    phase1_metrics = json.load(f)
                    phase1_usage = phase1_metrics.get("api_usage", {})
            
            # Parse Phase 2 metrics
            phase2_metrics_path = os.path.join(output_dir, "phase2_metrics.json")
            if os.path.exists(phase2_metrics_path):
                with open(phase2_metrics_path, 'r') as f:
                    phase2_metrics = json.load(f)
                    phase2_usage = phase2_metrics.get("api_usage", {})
            
            # Parse all Phase 3 iteration metrics
            for i in range(1, 31):  # Max 30 iterations
                iter_metrics_path = os.path.join(output_dir, f"phase3_iter_{i}_metrics.json")
                if os.path.exists(iter_metrics_path):
                    with open(iter_metrics_path, 'r') as f:
                        iter_metrics = json.load(f)
                        iter_usage = iter_metrics.get("api_usage", {})
                        if iter_usage.get("total_cost_usd", 0) > 0 or iter_usage.get("total_input_tokens", 0) > 0:
                            phase3_iterations.append((i, iter_usage))
            
            # Calculate totals
            total_cost = 0.0
            total_input_tokens = 0
            total_cache_creation = 0
            total_cache_read = 0
            total_output_tokens = 0
            
            for usage in [phase1_usage, phase2_usage] + [iter_data[1] for iter_data in phase3_iterations]:
                if usage:
                    total_cost += usage.get("total_cost_usd", 0)
                    total_input_tokens += usage.get("total_input_tokens", 0)
                    total_cache_creation += usage.get("total_cache_creation_tokens", 0)
                    total_cache_read += usage.get("total_cache_read_tokens", 0)
                    total_output_tokens += usage.get("total_output_tokens", 0)
            
            # Create summary report
            with open(summary_path, 'w') as f:
                f.write(f"# Token Usage Summary for {cve_id}\n\n")
                f.write(f"**Total Cost**: ${total_cost:.6f}\n")
                f.write(f"**Total Input Tokens**: {total_input_tokens:,}\n") 
                f.write(f"**Total Cache Creation Tokens**: {total_cache_creation:,}\n")
                f.write(f"**Total Cache Read Tokens**: {total_cache_read:,}\n")
                f.write(f"**Total Output Tokens**: {total_output_tokens:,}\n")
                f.write(f"**Effective Total Tokens**: {total_input_tokens + total_cache_creation + total_cache_read + total_output_tokens:,}\n\n")
                
                # Phase breakdown
                f.write("## Breakdown by Phase:\n")
                if phase1_usage:
                    f.write(f"- **Phase 1**: ${phase1_usage.get('total_cost_usd', 0):.6f} ({phase1_usage.get('total_input_tokens', 0) + phase1_usage.get('total_cache_read_tokens', 0) + phase1_usage.get('total_output_tokens', 0):,} tokens)\n")
                if phase2_usage:
                    f.write(f"- **Phase 2**: ${phase2_usage.get('total_cost_usd', 0):.6f} ({phase2_usage.get('total_input_tokens', 0) + phase2_usage.get('total_cache_read_tokens', 0) + phase2_usage.get('total_output_tokens', 0):,} tokens)\n")
                
                f.write(f"- **Phase 3 Iterations ({len(phase3_iterations)} iterations)**:\n")
                for iter_num, iter_usage in phase3_iterations:
                    iter_total_tokens = iter_usage.get('total_input_tokens', 0) + iter_usage.get('total_cache_read_tokens', 0) + iter_usage.get('total_output_tokens', 0)
                    f.write(f"  - Iteration {iter_num}: ${iter_usage.get('total_cost_usd', 0):.6f} ({iter_total_tokens:,} tokens)\n")
                
                f.write(f"\n## Summary Statistics:\n")
                f.write(f"- Total phases completed: {1 + (1 if phase2_usage else 0) + len(phase3_iterations)}\n")
                f.write(f"- Phase 3 iterations: {len(phase3_iterations)}\n")
                avg_iter_cost = (sum(iter_usage.get('total_cost_usd', 0) for _, iter_usage in phase3_iterations) / len(phase3_iterations)) if phase3_iterations else 0
                f.write(f"- Average cost per Phase 3 iteration: ${avg_iter_cost:.6f}\n")

            
            self.logger.info(f"Created comprehensive cost summary: {summary_path}")
            self.logger.info(f"Total actual cost: ${total_cost:.6f} across {1 + (1 if phase2_usage else 0) + len(phase3_iterations)} phases")
            
        except Exception as e:
            self.logger.error(f"Failed to create cost usage summary: {e}")
     
    def _create_refinement_prompt(self, task: VulnAnalysisTask, previous_feedback: str,
                                 iteration: int, collection_name: str) -> str:
        """Create prompt for query refinement based on previous feedback"""
        return self.backend.create_refinement_prompt(task, previous_feedback, iteration, collection_name)
    
    def _save_metadata(self, task: VulnAnalysisTask, result: Dict, start_time: datetime,
                      end_time: datetime, use_cache: bool, collection_name: str):
        """Save comprehensive iteration metadata with real API token usage"""
        
        # Calculate actual token usage from API data in metrics files
        output_dir = result["output_dir"]
        total_cost = 0.0
        total_input_tokens = 0
        total_cache_creation_tokens = 0
        total_cache_read_tokens = 0
        total_output_tokens = 0
        phase_tokens = {}
        
        # Parse actual API usage from metrics files
        for file_name in os.listdir(output_dir):
            if file_name.endswith("_metrics.json"):
                file_path = os.path.join(output_dir, file_name)
                try:
                    with open(file_path, 'r') as f:
                        metrics = json.load(f)
                        api_usage = metrics.get("api_usage", {})
                        
                    if api_usage and (api_usage.get("total_cost_usd", 0) > 0 or api_usage.get("total_input_tokens", 0) > 0):
                        # Extract real API usage data
                        phase_cost = api_usage.get("total_cost_usd", 0)
                        phase_input = api_usage.get("total_input_tokens", 0)
                        phase_cache_creation = api_usage.get("total_cache_creation_tokens", 0)
                        phase_cache_read = api_usage.get("total_cache_read_tokens", 0)
                        phase_output = api_usage.get("total_output_tokens", 0)
                        phase_total_tokens = phase_input + phase_cache_creation + phase_cache_read + phase_output
                        
                        # Accumulate totals
                        total_cost += phase_cost
                        total_input_tokens += phase_input
                        total_cache_creation_tokens += phase_cache_creation
                        total_cache_read_tokens += phase_cache_read
                        total_output_tokens += phase_output
                        
                        # Store phase breakdown
                        phase_tokens[file_name] = {
                            "cost_usd": phase_cost,
                            "input_tokens": phase_input,
                            "cache_creation_tokens": phase_cache_creation,
                            "cache_read_tokens": phase_cache_read,
                            "output_tokens": phase_output,
                            "total_tokens": phase_total_tokens
                        }
                    else:
                        phase_tokens[file_name] = {
                            "cost_usd": 0.0,
                            "note": "character_estimate_fallback"
                        }
                        
                except Exception as e:
                    self.logger.warning(f"Failed to parse API usage from {file_name}: {e}")
        
        total_effective_tokens = total_input_tokens + total_cache_creation_tokens + total_cache_read_tokens + total_output_tokens
        
        metadata = {
            "analysis_metadata": {
                "approach": "iterative_context_windows",
                "cve_id": task.cve_id,
                "total_iterations": result["total_iterations"],
                "success": result["success"],
                "duration_seconds": (end_time - start_time).total_seconds(),
                "collection_name": collection_name,
                "api_usage_summary": {
                    "total_cost_usd": total_cost,
                    "total_input_tokens": total_input_tokens,
                    "total_cache_creation_tokens": total_cache_creation_tokens,
                    "total_cache_read_tokens": total_cache_read_tokens,
                    "total_output_tokens": total_output_tokens,
                    "total_effective_tokens": total_effective_tokens
                },
                # Backward compatibility (deprecated)
                "total_estimated_tokens": int(total_effective_tokens),
                "token_breakdown_by_phase": phase_tokens,
                "iterations": [
                    {
                        "iteration": ir.iteration_number,
                        "query_path": ir.query_path,
                        "success": ir.success,
                        "vulnerable_results": ir.vulnerable_results,
                        "fixed_results": ir.fixed_results,
                        "compilation_successful": ir.compilation_successful,
                        "context_length": ir.context_length,
                        "compilation_summary": ir.compilation_summary,
                        "execution_summary": ir.execution_summary,
                        "error": ir.error
                    }
                    for ir in self.iteration_results
                ]
            },
            "file_inventory": {
                "all_outputs": [f for f in os.listdir(output_dir) if f.endswith(('.txt', '.json', '.ql', '.csv', '.bqrs'))],
                "agent_outputs": [f for f in os.listdir(output_dir) if f.endswith('_output.txt')],
                "metrics_files": [f for f in os.listdir(output_dir) if f.endswith('_metrics.json')],
                "query_files": [f for f in os.listdir(output_dir) if f.endswith('.ql')],
                "result_files": [f for f in os.listdir(output_dir) if f.endswith(('.csv', '.bqrs'))]
            }
        }
        
        metadata_path = os.path.join(output_dir, "iterative_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Saved metadata: {metadata_path}")
        self.logger.info(f"Real API cost: ${total_cost:.6f}")
        self.logger.info(f"Total effective tokens: {total_effective_tokens:,} (input: {total_input_tokens:,}, cache: {total_cache_read_tokens:,}, output: {total_output_tokens:,})")
        self.logger.info(f"Completed {result['total_iterations']} iterations")


class QLAgentIterativeCLI:
    def __init__(self, working_dir: str = None, agent_type: str = "claude", model: str = "sonnet-4",
                 ablation_mode: str = "full", codex_use_local_config: bool = False,
                 claude_use_local_config: bool = False):
        self.agent = QLAgentIterative(working_dir, agent_type=agent_type, model=model,
                                      ablation_mode=ablation_mode,
                                      codex_use_local_config=codex_use_local_config,
                                      claude_use_local_config=claude_use_local_config)
    
    def discover_cve_paths(self, cve_id: str) -> tuple:
        """Discover database and diff paths from CVE ID"""
        cve_dir = os.path.join(CVES_PATH, cve_id)
        
        if not os.path.exists(cve_dir):
            raise FileNotFoundError(f"CVE directory not found: {cve_dir}")
        
        vuln_db = os.path.join(cve_dir, f"{cve_id}-vul")
        fixed_db = os.path.join(cve_dir, f"{cve_id}-fix")
        diff_file = os.path.join(cve_dir, f"{cve_id}.diff")
        
        missing_paths = []
        if not os.path.exists(vuln_db):
            missing_paths.append(f"Vulnerable DB: {vuln_db}")
        if not os.path.exists(fixed_db):
            missing_paths.append(f"Fixed DB: {fixed_db}")
        if not os.path.exists(diff_file):
            missing_paths.append(f"Diff file: {diff_file}")
        
        if missing_paths:
            raise FileNotFoundError(f"Missing required files for {cve_id}:\n" + "\n".join(missing_paths))
        
        return vuln_db, fixed_db, diff_file
    
    async def analyze_vulnerability(self, cve_id: str, vuln_db: str = None, fixed_db: str = None,
                                   diff_file: str = None, 
                                   output_dir: str = None, max_iteration: int = 5,
                                   cache_phase_output: bool = True,
                                   model: str = "sonnet-4") -> None:
        
        # Auto-discover paths if not provided
        if not all([vuln_db, fixed_db, diff_file]):
            try:
                discovered_vuln_db, discovered_fixed_db, discovered_diff_file = self.discover_cve_paths(cve_id)
                vuln_db = vuln_db or discovered_vuln_db
                fixed_db = fixed_db or discovered_fixed_db
                diff_file = diff_file or discovered_diff_file
                print(f"Auto-discovered paths for {cve_id}")
            except FileNotFoundError as e:
                print(f"{e}")
                return
        
        try:
            with open(diff_file, 'r', encoding='utf-8', errors='replace') as f:
                diff_content = f.read()
        except Exception as e:
            print(f"Failed to read diff file: {e}")
            return

        processed_diff, diff_metadata = preprocess_diff_for_prompt(diff_content)
        if diff_metadata.get("truncated"):
            print(
                "Preprocessed diff for prompt use: "
                f"{diff_metadata['original_chars']:,} -> {diff_metadata['processed_chars']:,} chars; "
                f"included {diff_metadata['included_patch_count']}/{diff_metadata['original_patch_count']} patches."
            )

        task = VulnAnalysisTask(
            vuln_db_path=vuln_db,
            fixed_db_path=fixed_db,
            fix_commit_diff=processed_diff,
            cve_id=cve_id,
            output_dir=output_dir or "output",
            working_dir=None,  # Will be set when we know the actual working directory
            max_iteration=max_iteration,
            model=model,
            ast_cache=AST_CACHE,
            nvd_cache=NVD_CACHE,
        )

        # Load pre-fetched CVE description for ablation modes that skip Chroma
        if self.agent.backend.ablation_mode in ("no_tools", "no_docs"):
            if os.path.exists(CVE_DESCRIPTIONS_FILE):
                with open(CVE_DESCRIPTIONS_FILE, 'r', encoding='utf-8') as f:
                    descriptions = json.load(f)
                task.cve_description = descriptions.get(cve_id)
                if task.cve_description:
                    print(f"Loaded CVE description from {CVE_DESCRIPTIONS_FILE}")
                else:
                    print(f"Warning: no description found for {cve_id} in {CVE_DESCRIPTIONS_FILE}")
            else:
                print(f"Warning: {CVE_DESCRIPTIONS_FILE} not found; cve_description will be empty")
         
        print(f"Starting Iterative Vulnerability Analysis")
        print(f"CVE ID: {cve_id}")
        print(f"Max iterations: {max_iteration}")
        print(f"Model: {model}")
        
        result = await self.agent.run_iterative_analysis(task, use_cache=cache_phase_output)
        
        if result["success"]:
            print("Iterative analysis completed successfully!")
            print(f"Results: {result.get('output_dir')}")
            print(f"Total iterations: {result['total_iterations']}")
            if result.get("final_query"):
                print(f"Final query: {result['final_query']}")
        else:
            print("Iterative analysis failed!")
            print(f"Error: {result.get('error')}")
            print(f"Completed iterations: {result.get('total_iterations', 0)}")


async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="QLCoder Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--cve-id", required=True, help="CVE identifier")
    parser.add_argument("--vuln-db", help="Path to vulnerable CodeQL database")
    parser.add_argument("--fixed-db", help="Path to fixed CodeQL database")
    parser.add_argument("--diff", help="Path to fix commit diff file")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--max-iteration", default=5, type=int, help="Max iterations")
    parser.add_argument("--cache-phase-output", action="store_true", default=True)
    parser.add_argument("--no-cache-phase-output", dest="cache_phase_output", action="store_false")
    parser.add_argument("--model", default="sonnet-4",
                        choices=["sonnet-4", "sonnet-4.5", "gemini-2.5-pro", "gemini-2.5-flash", "gpt-5", "gpt-5.4"])
    parser.add_argument("--agent", default="claude", choices=["claude", "gemini", "codex"],
                        help="Agent backend to use")
    parser.add_argument(
        "--codex-use-local-config",
        action="store_true",
        help="For --agent codex, reuse ~/.codex/config.toml and skip API-key login/model override",
    )
    parser.add_argument(
        "--claude-use-local-config",
        action="store_true",
        help="For --agent claude, reuse local Claude Code CLI credentials and skip ANTHROPIC_API_KEY injection",
    )
    parser.add_argument("--ablation-mode", default="full",
                        choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"],
                        help="Ablation mode (default: full)")

    args = parser.parse_args()

    if args.agent == "codex" and args.codex_use_local_config:
        try:
            try:
                from .agent_backends.codex_backend import get_local_codex_model
            except ImportError:
                from agent_backends.codex_backend import get_local_codex_model

            configured_model = get_local_codex_model()
            if configured_model:
                args.model = configured_model
                print(f"Detected Codex model from ~/.codex/config.toml: {configured_model}")
            else:
                print("Warning: no model found in ~/.codex/config.toml; Codex CLI default will be used")
        except Exception as e:
            print(f"Warning: failed to read ~/.codex/config.toml: {e}")

    if args.agent == "claude" and args.claude_use_local_config:
        try:
            try:
                from .agent_backends.claude_backend import get_local_claude_model
            except ImportError:
                from agent_backends.claude_backend import get_local_claude_model

            configured_model = get_local_claude_model()
            if configured_model:
                args.model = configured_model
                print(f"Detected Claude model from ~/.claude/settings.json: {configured_model}")
            else:
                print("Warning: no model found in ~/.claude/settings.json; will use command-line --model value")
        except Exception as e:
            print(f"Warning: failed to read ~/.claude/settings.json: {e}")

    cli = QLAgentIterativeCLI(agent_type=args.agent, model=args.model,
                              ablation_mode=args.ablation_mode,
                              codex_use_local_config=args.codex_use_local_config,
                              claude_use_local_config=args.claude_use_local_config)
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
