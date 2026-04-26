#!/usr/bin/env python3

import asyncio
import subprocess
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import tempfile
import pandas as pd
try:
    from .config import CODEQL_PATH
except ImportError:
    from config import CODEQL_PATH

@dataclass
class QueryResult:
    """Container for query execution results"""
    query_path: str
    database_path: str
    database_type: str  # "vulnerable" or "fixed"
    bqrs_path: str
    csv_path: str
    sarif_path: str  # Added for evaluation
    success: bool
    error: Optional[str] = None
    num_results: int = 0


@dataclass
class EvaluationResult:
    """Container for detailed evaluation results"""
    recall_method: bool
    num_tp_methods: int
    total_fixed_methods: int
    num_results: int
    num_paths: int
    fixed_methods: List[str]
    hit_methods: List[str]
    missed_methods: List[str]
    # File-level tracking
    recall_file: bool
    num_tp_files: int
    total_fixed_files: int
    fixed_files: List[str]
    hit_files: List[str]
    missed_files: List[str]
    full_result: dict[str, Any]

class QueryExecutionSubagent:
    """Subagent for executing CodeQL queries in parallel on both databases"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.codeql_path = CODEQL_PATH
    
    async def run_query_on_database(
        self, 
        query_path: str, 
        database_path: str, 
        database_type: str,
        iteration_number: int = 1,
        output_dir: Optional[str] = None
    ) -> QueryResult:
        """Run a single CodeQL query on a database and generate both CSV and SARIF results"""
        
        if output_dir is None:
            output_dir = os.path.dirname(query_path)
        
        # Create unique output file names with iteration number
        base_name = f"{Path(query_path).stem}_{database_type}"
        if iteration_number > 1:
            base_name += f"_iter_{iteration_number}"
        
        bqrs_path = os.path.join(output_dir, f"{base_name}_results.bqrs")
        csv_path = os.path.join(output_dir, f"{base_name}_results.csv")
        sarif_path = os.path.join(output_dir, f"{base_name}_results.sarif")
        
        try:
            self.logger.info(f"Running query on {database_type} database")
            
            # Step 1: Run CodeQL query to generate BQRS
            await self._run_codeql_query(query_path, database_path, bqrs_path)
            
            # Step 2: Decode BQRS to CSV
            await self._decode_bqrs_to_csv(bqrs_path, csv_path)
            
            # Step 3: Generate SARIF for detailed evaluation
            await self._generate_sarif(query_path, database_path, sarif_path)
            
            # Step 4: Count results
            num_results = self._count_csv_results(csv_path)
            
            # Step 5: Clean database cache to prevent lock issues
            await self._cleanup_database_cache(database_path)
            
            self.logger.info(f"{database_type} DB: {num_results} results (cache cleaned)")
            
            return QueryResult(
                query_path=query_path,
                database_path=database_path,
                database_type=database_type,
                bqrs_path=bqrs_path,
                csv_path=csv_path,
                sarif_path=sarif_path,
                success=True,
                num_results=num_results,
            )
            
        except Exception as e:
            self.logger.error(f"Query failed on {database_type}: {e}")
            
            return QueryResult(
                query_path=query_path,
                database_path=database_path,
                database_type=database_type,
                bqrs_path=bqrs_path,
                csv_path=csv_path,
                sarif_path=sarif_path,
                success=False,
                error=str(e)
            )
    
    async def _run_codeql_query(self, query_path: str, database_path: str, output_path: str):
        """Execute CodeQL query and save results to BQRS"""
        cmd = [
            self.codeql_path, "query", "run",
            "--database", database_path,
            "--output", output_path,
            "--", query_path
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"CodeQL query failed: {stderr.decode()}")
    
    async def _decode_bqrs_to_csv(self, bqrs_path: str, csv_path: str):
        """Decode BQRS file to CSV format"""
        cmd = [
            self.codeql_path, "bqrs", "decode",
            "--format=csv",
            f"--output={csv_path}",
            bqrs_path
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"BQRS decode failed: {stderr.decode()}")
    
    async def _generate_sarif(self, query_path: str, database_path: str, sarif_path: str):
        """Generate SARIF output using database analyze"""
        self.logger.info("Generating SARIF format")
        cmd = [
            self.codeql_path, "database", "analyze",
            database_path,
            query_path,
            "--format=sarif-latest",
            "--output", sarif_path,
            "--rerun"
        ]
        
        self.logger.info(f"Generating SARIF: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        stdout_str = stdout.decode() if stdout else ""
        stderr_str = stderr.decode() if stderr else ""
        
        if process.returncode != 0:
            self.logger.error(f"SARIF generation failed with return code {process.returncode}")
            self.logger.error(f"STDOUT: {stdout_str}")
            self.logger.error(f"STDERR: {stderr_str}")
            # Create empty SARIF file so evaluation doesn't crash
            self.logger.info(f"Creating empty SARIF file: {sarif_path}")
            with open(sarif_path, 'w') as f:
                json.dump({"runs": [{"results": []}]}, f)
        else:
            self.logger.info(f"SARIF generation successful: {sarif_path}")
            if os.path.exists(sarif_path):
                self.logger.info(f"SARIF file size: {os.path.getsize(sarif_path)} bytes")
            else:
                self.logger.error(f"SARIF file was not created despite success: {sarif_path}")
    
    def _count_csv_results(self, csv_path: str) -> int:
        """Count results in CSV file"""
        try:
            if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
                return 0
            
            with open(csv_path, 'r') as f:
                # Count lines minus header
                lines = f.readlines()
                return max(0, len(lines) - 1)
                
        except Exception as e:
            self.logger.error(f"Failed to count CSV results: {e}")
            return 0
    
    async def _cleanup_database_cache(self, database_path: str):
        """Clean database cache to prevent locking issues"""
        try:
            cmd = [
                self.codeql_path, "database", "cleanup",
                database_path,
                "--cache-cleanup=clear"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.warning(f"Database cleanup warning: {stderr.decode()}")
            else:
                self.logger.debug(f"Successfully cleaned database cache: {database_path}")
                
        except Exception as e:
            self.logger.warning(f"Failed to cleanup database cache: {e}")


class EvaluationCalculator:
    """Calculate detailed evaluation metrics using evaluation.py logic"""
    
    def __init__(self, cve_id: str, logger: Optional[logging.Logger] = None):
        self.cve_id = cve_id
        self.logger = logger or logging.getLogger(__name__)
    
    def evaluate_sarif_result(self, sarif_path: str, database_path: str) -> EvaluationResult:
        """Evaluate SARIF results using QueryEvaluator from evaluation.py - simplified approach"""
        try:
            try:
                from src.evaluation import QueryEvaluator
            except ImportError:
                from evaluation import QueryEvaluator
            
            # Create temporary output path for evaluator
            temp_output = sarif_path.replace('.sarif', '_eval.json')
            
            # Initialize evaluator (same as evaluation.py does)
            evaluator = QueryEvaluator(
                input_dir=os.path.dirname(sarif_path),
                cve_id=self.cve_id,
                diff_file="",  # Not used for SARIF evaluation
                final_output_json_path=temp_output,
                database_path=database_path,
                logger=self.logger
            )
            
            # DEBUG: Show fixed locations that evaluator expects
            self.logger.info(f"Database path: {database_path}")
            self.logger.info(f"SARIF path: {sarif_path}")
            self.logger.info(f"Expected fixed files: {evaluator.fixed_locations['files']}")
            self.logger.info(f"Expected fixed methods: {evaluator.fixed_locations['methods']}")
            
            # Use evaluation.py exactly as it works - no complex method matching
            result = evaluator.evaluate_sarif_result(sarif_path, "", database_path)
            
            # DEBUG: Show detailed evaluation results
            self.logger.info(f"Raw evaluation result: {result}")
            self.logger.info(f"Recall method: {result.get('recall_method', False)}")
            self.logger.info(f"Recall file: {result.get('recall_file', False)}")
            self.logger.info(f"Num TP methods: {result.get('num_tp_results_method', 0)}")
            self.logger.info(f"Num TP files: {result.get('num_tp_results_file', 0)}")
            self.logger.info(f"Total results: {result.get('num_results', 0)}")
            self.logger.info(f"Total paths: {result.get('num_paths', 0)}")
            
            # DEBUG: Read and analyze the SARIF file to see what methods we actually found
            try:
                import json
                with open(sarif_path, 'r') as f:
                    sarif_data = json.load(f)
                
                self.logger.info("=== SARIF ANALYSIS ===")
                found_methods = set()
                found_files = set()
                
                # Extract methods from code flows
                for result_id, result_obj, code_flow in evaluator._iter_code_flows(sarif_data):
                    passing_methods = evaluator._extract_code_flow_passing_methods(code_flow, database_path)
                    passing_files = evaluator._extract_code_flow_passing_files(code_flow)
                    
                    found_methods.update(passing_methods)
                    found_files.update(passing_files)
                    
                    self.logger.info(f"Code flow {result_id}: methods={passing_methods}, files={passing_files}")
                
                self.logger.info(f"All found methods: {found_methods}")
                self.logger.info(f"All found files: {found_files}")
                
                # Check intersections
                method_intersect = evaluator.fixed_locations['methods'].intersection(found_methods)
                file_intersect = evaluator.fixed_locations['files'].intersection(found_files)
                
                self.logger.info(f"Method intersection: {method_intersect}")
                self.logger.info(f"File intersection: {file_intersect}")
                
            except Exception as debug_e:
                self.logger.error(f"Debug SARIF analysis failed: {debug_e}")
            
            # Extract exact hit/miss information from SARIF analysis
            fixed_methods = result.get("fixed_methods", [])
            fixed_files = result.get("fixed_files", [])
            recall_method = result.get("recall_method", False)
            recall_file = result.get("recall_file", False)
            num_tp_methods = result.get("num_tp_results_method", 0)
            num_tp_files = result.get("num_tp_results_file", 0)
            
            # Use the exact SARIF-extracted data - found_methods and found_files are the precise hits
            # These are always created above, so we can always use them
            hit_methods = list(found_methods)
            hit_files = list(found_files)
            
            # Calculate missed items by comparing with targets
            fixed_methods_set = set(fixed_methods) 
            fixed_files_set = set(fixed_files)
            
            missed_methods = list(fixed_methods_set - found_methods)
            missed_files = list(fixed_files_set - found_files)
            
            self.logger.info(f"Final evaluation result for {database_path}: recall={recall_method}")
            self.logger.info("=== END DEBUGGING ===")
            return EvaluationResult(
                recall_method=recall_method,
                num_tp_methods=num_tp_methods,
                total_fixed_methods=len(fixed_methods),
                num_results=result.get("num_results", 0),
                num_paths=result.get("num_paths", 0),
                fixed_methods=fixed_methods,
                hit_methods=hit_methods,
                missed_methods=missed_methods,
                # File-level tracking
                recall_file=recall_file,
                num_tp_files=num_tp_files,
                total_fixed_files=len(fixed_files),
                fixed_files=fixed_files,
                hit_files=hit_files,
                missed_files=missed_files,
                full_result=result
            )

        except Exception as e:
            self.logger.error(f"Evaluation failed: {e}")
            return EvaluationResult(
                recall_method=False,
                num_tp_methods=0,
                total_fixed_methods=0,
                num_results=0,
                num_paths=0,
                fixed_methods=[],
                hit_methods=[],
                missed_methods=[],
                # File-level tracking
                recall_file=False,
                num_tp_files=0,
                total_fixed_files=0,
                fixed_files=[],
                hit_files=[],
                missed_files=[],
                full_result={},\
            )
    
    def _extract_hit_methods_from_sarif(self, sarif_path: str, evaluator) -> List[str]:
        """Extract which methods were actually hit from SARIF"""
        try:
            if not os.path.exists(sarif_path):
                return []

            with open(sarif_path, 'r') as f:
                sarif_data = json.load(f)

            hit_methods = set()

            # Use evaluator's logic to extract methods from code flows
            for result_id, result, code_flow in evaluator._iter_code_flows(sarif_data):
                passing_methods = evaluator._extract_code_flow_passing_methods(code_flow, evaluator.database_path)
                hit_methods.update(passing_methods)

            # Filter to only include fixed methods that were hit
            fixed_methods = set(evaluator.fixed_locations["methods"])
            return list(hit_methods.intersection(fixed_methods))

        except Exception as e:
            self.logger.error(f"Failed to extract hit methods: {e}")
            return [] 

    def _format_location_with_method(self, location_obj: dict, database_path: str, evaluator) -> Optional[str]:
        """Format a SARIF location showing the expression/variable and containing method.

        Format: 'path/to/file.java:ClassName:methodName'
        """
        try:
            phys_loc = location_obj.get('location', {}).get('physicalLocation', {})
            artifact_loc = phys_loc.get('artifactLocation', {})
            region = phys_loc.get('region', {})

            file_uri = artifact_loc.get('uri', '')
            start_line = region.get('startLine', 0)

            # Get the expression/variable at this location
            message = location_obj.get('location', {}).get('message', {}).get('text', '')

            if not file_uri or not start_line:
                return None

            # Try to get containing method using evaluator's method extraction
            mini_code_flow = {
                'threadFlows': [{
                    'locations': [location_obj]
                }]
            }

            # Extract the containing method
            methods = evaluator._extract_code_flow_passing_methods(mini_code_flow, database_path)

            if methods:
                # Get the method signature from evaluator
                # Format returned by evaluator: "path/file.java:ClassName:methodName"
                full_method_sig = list(methods)[0]

                # The method signature is already in the correct format, just return it
                return full_method_sig

            # Fallback if method extraction fails
            return self._format_location_simple(location_obj, file_uri, start_line, message)

        except Exception as e:
            self.logger.error(f"Failed to format location with method: {e}")
            # Fallback to simple formatting
            try:
                phys_loc = location_obj.get('location', {}).get('physicalLocation', {})
                artifact_loc = phys_loc.get('artifactLocation', {})
                region = phys_loc.get('region', {})
                file_uri = artifact_loc.get('uri', '')
                start_line = region.get('startLine', 0)
                message = location_obj.get('location', {}).get('message', {}).get('text', '')
                return self._format_location_simple(location_obj, file_uri, start_line, message)
            except:
                return None

    def _format_location_simple(self, location_obj: dict, file_uri: str, start_line: int, message: str = None) -> str:
        """Fallback simple formatting for locations"""
        if message is None:
            message = location_obj.get('location', {}).get('message', {}).get('text', '')

        # Extract class name from file path (if Java)
        class_name = "unknown"
        if file_uri.endswith('.java'):
            file_name = file_uri.split('/')[-1].replace('.java', '')
            class_name = file_name

        # Format: file:line:Class:expression
        #return f"{file_uri}:{start_line}:{class_name}:{message}"
        return f"{file_uri}:{class_name}:{message}"
    def _format_location(self, location_obj: dict, database_path: str) -> Optional[str]:
        """Format a SARIF location as 'path/to/file.java:ClassName:methodName'"""
        try:
            phys_loc = location_obj.get('location', {}).get('physicalLocation', {})
            artifact_loc = phys_loc.get('artifactLocation', {})
            file_uri = artifact_loc.get('uri', '')

            if not file_uri:
                return None

            # Get message which often contains method information
            message = location_obj.get('location', {}).get('message', {}).get('text', '')

            # Try to extract class and method from file path and message
            # Format: "path/to/file.java:Class:method"

            # Extract class name from file path (if Java)
            class_name = ""
            method_name = ""

            if file_uri.endswith('.java'):
                # Try to get class name from file path
                file_name = file_uri.split('/')[-1].replace('.java', '')
                class_name = file_name

            # Parse message for method information
            # Common patterns: "method : Method", "call to method", etc.
            if ':' in message:
                parts = message.split(':')
                if len(parts) >= 1:
                    method_name = parts[0].strip()
            else:
                method_name = message.strip()

            # Format as requested
            if class_name and method_name:
                return f"{file_uri}:{class_name}:{method_name}"
            elif method_name:
                return f"{file_uri}:unknown:{method_name}"
            else:
                return f"{file_uri}:unknown:unknown"

        except Exception as e:
            self.logger.error(f"Failed to format location: {e}")
            return None


class CompilationSubagent:
    """Subagent for compiling queries and providing real-time feedback"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.codeql_path = CODEQL_PATH
    
    async def compile_query(self, query_path: str) -> Dict:
        """Compile a CodeQL query and return compilation results"""
        try:
            self.logger.info(f"Compiling query: {query_path}")
            
            cmd = [
                self.codeql_path, "query", "compile",
                query_path
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result = {
                "query_path": query_path,
                "success": process.returncode == 0,
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
                "return_code": process.returncode
            }
            
            if result["success"]:
                self.logger.info("Query compiled successfully")
            else:
                self.logger.error(f"Compilation failed: {stderr.decode()}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Compilation process failed: {e}")
            return {
                "query_path": query_path,
                "success": False,
                "error": str(e),
                "return_code": -1
            }
    
    def summarize_compilation_errors(self, compilation_result: Dict) -> str:
        """Generate concise summary of compilation errors"""
        if compilation_result["success"]:
            return "COMPILATION SUCCESS: Query syntax is valid"
        
        stderr = compilation_result.get("stderr", "")
        
        # Extract common error patterns
        lines = []
        lines.append("COMPILATION FAILED:")
        
        # Parse common CodeQL compilation errors
        if "syntax error" in stderr.lower():
            lines.append("  • Syntax Error: Check brackets, semicolons, keywords")
        
        if "could not resolve" in stderr.lower():
            lines.append("  • Resolution Error: Check imports and class/predicate names")
        
        if "type error" in stderr.lower():
            lines.append("  • Type Error: Check variable types and method signatures")
        
        if "duplicate" in stderr.lower():
            lines.append("  • Duplicate Definition: Check for repeated class/predicate names")
        
        # Extract specific error lines 
        error_lines = [line.strip() for line in stderr.split('\n') if 'error' in line.lower()]
        if error_lines:
            lines.append("  Specific errors:")
            for error_line in error_lines:
                lines.append(f"    - {error_line[:100]}...")
        
        return "\n".join(lines)


class ParallelQueryExecutor:
    """Run queries on both databases with detailed evaluation"""
    
    def __init__(self, cve_id: str, logger: Optional[logging.Logger] = None):
        self.cve_id = cve_id
        self.logger = logger or logging.getLogger(__name__)
        self.subagent = QueryExecutionSubagent(logger)
        self.evaluator = EvaluationCalculator(cve_id, logger)
    
    async def run_and_get_evaluation_results(
        self,
        query_path: str,
        vuln_db_path: str,
        fixed_db_path: str,
        iteration_number: int = 1,
        output_dir: Optional[str] = None
    ) -> tuple[str, EvaluationResult, EvaluationResult, bool]:
        """Run query and return detailed evaluation results"""
        
        # Run queries in parallel
        vuln_task = self.subagent.run_query_on_database(
            query_path, vuln_db_path, "vulnerable", iteration_number, output_dir
        )
        
        fixed_task = self.subagent.run_query_on_database(
            query_path, fixed_db_path, "fixed", iteration_number, output_dir
        )
        
        vuln_result, fixed_result = await asyncio.gather(vuln_task, fixed_task)
        
        # Perform detailed evaluation on both results
        vuln_eval = EvaluationResult(
            recall_method=False, num_tp_methods=0, total_fixed_methods=0, 
            num_results=0, num_paths=0, fixed_methods=[], hit_methods=[], missed_methods=[],
            recall_file=False, num_tp_files=0, total_fixed_files=0, 
            fixed_files=[], hit_files=[], missed_files=[], full_result={}
        )
        fixed_eval = EvaluationResult(
            recall_method=False, num_tp_methods=0, total_fixed_methods=0,
            num_results=0, num_paths=0, fixed_methods=[], hit_methods=[], missed_methods=[],
            recall_file=False, num_tp_files=0, total_fixed_files=0,
            fixed_files=[], hit_files=[], missed_files=[], full_result={}
        )
        if vuln_result.success and os.path.exists(vuln_result.sarif_path):
            vuln_eval = self.evaluator.evaluate_sarif_result(vuln_result.sarif_path, vuln_db_path)

        if fixed_result.success and os.path.exists(fixed_result.sarif_path):
            fixed_eval = self.evaluator.evaluate_sarif_result(fixed_result.sarif_path, fixed_db_path)
        # Generate enhanced summary
        summary = self._generate_evaluation_summary(
            vuln_result, fixed_result, vuln_eval, fixed_eval, iteration_number
        )
        
        execution_successful = vuln_result.success and fixed_result.success
        
        return summary, vuln_eval, fixed_eval, execution_successful
    
    def _generate_evaluation_summary(
        self, 
        vuln_result: QueryResult, 
        fixed_result: QueryResult, 
        vuln_eval: EvaluationResult,
        fixed_eval: EvaluationResult,
        iteration_number: int
    ) -> str:
        """Generate detailed evaluation summary"""
        
        lines = [f"## Query Evaluation Summary (Iteration {iteration_number})"]
        # Execution status
        if not vuln_result.success or not fixed_result.success:
            lines.append("EXECUTION FAILED")
            if not vuln_result.success:
                lines.append(f"  Vulnerable DB: {vuln_result.error}")
            if not fixed_result.success:
                lines.append(f"  Fixed DB: {fixed_result.error}")
            return "\n".join(lines)
        
        # Basic result counts
        lines.append(f"Results: Vulnerable={vuln_result.num_results}, Fixed={fixed_result.num_results}")
        
        # Detailed evaluation metrics
        lines.append(f"Method Recall: Vulnerable={vuln_eval.recall_method}, Fixed={fixed_eval.recall_method}")
        lines.append(f"True Positive Methods: Vulnerable={vuln_eval.num_tp_methods}, Fixed={fixed_eval.num_tp_methods}")
        # Show coverage based on target methods actually hit (consistent with display below)
        target_methods_set = set(vuln_eval.fixed_methods) if hasattr(vuln_eval, 'fixed_methods') else set()
        hit_methods_set = set(vuln_eval.hit_methods) if vuln_eval.hit_methods else set()
        actual_target_hit_count = len(target_methods_set.intersection(hit_methods_set))
        lines.append(f"Coverage: {actual_target_hit_count}/{vuln_eval.total_fixed_methods} target methods")
        
        # Success assessment
        if vuln_eval.recall_method and not fixed_eval.recall_method:
            lines.append("EXCELLENT: Query hits target methods in vulnerable version only")
        elif vuln_eval.recall_method and fixed_eval.recall_method:
            lines.append("PARTIAL: Query hits targets but has false positives in fixed version")
        elif not vuln_eval.recall_method:
            lines.append("MISS: Query does not hit any target vulnerable methods")
        
        # Hit method details with locations - only show TARGET methods that were hit
        target_methods_set = set(vuln_eval.fixed_methods) if hasattr(vuln_eval, 'fixed_methods') else set()
        hit_methods_set = set(vuln_eval.hit_methods) if vuln_eval.hit_methods else set()
        successfully_targeted = list(target_methods_set.intersection(hit_methods_set))
        lines.append("Method location format is path/to/hit/file.java:Class:Method") 
        if successfully_targeted:
            lines.append("Successfully targeted methods:")
            for method in successfully_targeted:
                lines.append(f"  - {method}")
                 
        if vuln_eval.missed_methods:
            lines.append("Missed target methods:")
            for method in vuln_eval.missed_methods:
                # Show full method path for better context
                method_name = method
                lines.append(f"  - {method_name}")
        
        # False positives in fixed version - only show TARGET methods hit in fixed version
        if fixed_eval.recall_method and fixed_eval.hit_methods:
            # False positives = target methods that are still hit in the fixed version
            target_methods_set = set(vuln_eval.fixed_methods) if hasattr(vuln_eval, 'fixed_methods') else set()
            fixed_hit_methods_set = set(fixed_eval.hit_methods)
            false_positives = list(target_methods_set.intersection(fixed_hit_methods_set))
            
            if false_positives:
                lines.append("False positives (hits in fixed version):")
                for method in false_positives[:3]:
                    lines.append(f"  - {method}")
        
        
        return "\n".join(lines)


# Integration functions for backward compatibility
async def run_query_with_evaluation_results(
    query_path: str,
    vuln_db_path: str,
    fixed_db_path: str,
    cve_id: str,
    iteration_number: int = 1,
    output_dir: Optional[str] = None,
    logger: Optional[logging.Logger] = None
) -> tuple[str, EvaluationResult, EvaluationResult, bool]:
    """Run query and return detailed evaluation results"""
    
    if logger is None:
        logger = logging.getLogger(__name__)
    
    executor = ParallelQueryExecutor(cve_id, logger)
    
    return await executor.run_and_get_evaluation_results(
        query_path, vuln_db_path, fixed_db_path, iteration_number, output_dir
    )


# Compilation functions
async def compile_query_once(
    query_path: str,
    logger: Optional[logging.Logger] = None
) -> str:
    """Compile query once and return concise summary"""
    
    if logger is None:
        logger = logging.getLogger(__name__)
    
    compiler = CompilationSubagent(logger)
    result = await compiler.compile_query(query_path)
    summary = compiler.summarize_compilation_errors(result)
    
    return summary


if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 5:
            print("Usage: python query_subagents_evaluation.py <query_path> <vuln_db> <fixed_db> <cve_id>")
            sys.exit(1)
        
        query_path = sys.argv[1]
        vuln_db = sys.argv[2]
        fixed_db = sys.argv[3]
        cve_id = sys.argv[4]
        
        summary, vuln_eval, fixed_eval, success = await run_query_with_evaluation_results(
            query_path, vuln_db, fixed_db, cve_id
        )
        print(summary)
        print(f"\nDetailed Results:")
        print(f"Vulnerable DB - Recall: {vuln_eval.recall_method}, TP Methods: {vuln_eval.num_tp_methods}")
        print(f"Fixed DB - Recall: {fixed_eval.recall_method}, TP Methods: {fixed_eval.num_tp_methods}")
    
    asyncio.run(main())