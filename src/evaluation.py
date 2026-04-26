#!/usr/bin/env python3

# Set to True to enable support for problem queries with locations
# Set to False to use original behavior (only code flows)
ENABLE_LOCATION_SUPPORT = True

import json
import re
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
import logging
import pandas as pd
try:
    from .config import FIX_INFO, QUERIES_PATH
except ImportError:
    from config import FIX_INFO, QUERIES_PATH 

@dataclass(frozen=True)
class CodeLocation:
    file_path: str
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    line_number: Optional[int] = None
    
    def to_method_key(self) -> str:
        """Convert to file:class:method format"""
        return f"{self.file_path}:{self.class_name or ''}:{self.method_name or ''}"
    
    def to_file_key(self) -> str:
        """Convert to file format"""
        return self.file_path

class QueryEvaluator:
    """Evaluates CodeQL query results against CVE fixed methods and files to calculate true positives"""
    
    def __init__(self, input_dir: str, cve_id: str, diff_file: str, final_output_json_path: str, database_path: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.cve_id = cve_id
        self.diff_file = diff_file
        self.input_dir = input_dir
        self.database_path = database_path
        self.logger = logger or logging.getLogger(__name__)
        self.fix_data = FIX_INFO 
        self.fixed_locations = self._extract_fixed_locations()
        self.project_classes = None
        self.project_methods = None
        self.final_output_json_path = final_output_json_path
    
    def _is_test_file(self, file_path: str) -> bool:
        """Determine if a file is a test file based on path and naming conventions

        Returns True if the file is likely a test file, False otherwise.
        """
        file_path_lower = file_path.lower()
        basename = os.path.basename(file_path_lower)

        # Check if file is in a test directory
        if "/test/" in file_path_lower or "/tests/" in file_path_lower:
            return True

        # Check if file follows test naming conventions
        if (basename.endswith("test.java") or
            basename.endswith("tests.java") or
            basename.startswith("test") or
            basename.endswith("testcase.java") or
            "unittest" in basename or
            "integrationtest" in basename):
            return True

        # Check for common test class patterns
        if any(pattern in basename for pattern in [
            "testutil", "testhelper", "testbase", "abstracttest",
            "mocktest", "dummytest"
        ]):
            return True

        return False
     
    def _normalize_sarif_path(self, uri: str) -> str:
        """Normalize SARIF URI paths to match expected format
        
        Handles both absolute and relative paths by finding 'src' component
        and extracting from there onwards.
        
        Examples:
        - "vertx-web/src/main/java/Foo.java" -> "src/main/java/Foo.java" 
        - "/some/absolute/vertx-web/src/main/java/Foo.java" -> "src/main/java/Foo.java"
        - "src/main/java/Foo.java" -> "src/main/java/Foo.java" (no change)
        """
        normalized_uri = uri.replace('file://', '')
        parts = normalized_uri.split('/')
        
        if 'src' in parts:
            idx = parts.index('src')
            normalized_uri = '/'.join(parts[idx:])
            
        return normalized_uri
    
    def _generate_sarif_path_variants(self, uri: str) -> set:
        """Generate multiple path variants for flexible SARIF path matching
        
        Handles inconsistent path formats by generating variants for both:
        - Pattern 1: "src/main/java/Foo.java" (direct src paths)  
        - Pattern 2: "module/src/main/java/Foo.java" (module-prefixed paths)
        
        Returns set of possible path representations to match against expected paths.
        """
        normalized_uri = uri.replace('file://', '')
        parts = normalized_uri.split('/')
        
        path_variants = set()
        
        if 'src' in parts:
            src_idx = parts.index('src')
            
            # Pattern 1: Strip to src/ (for CVEs like CVE-2016-5394)
            src_path = '/'.join(parts[src_idx:])
            path_variants.add(src_path)
            
            # Pattern 2: Keep 1-2 directories before src/ (for CVEs like CVE-2025-0851)
            for start_idx in range(max(0, src_idx - 2), src_idx):
                if (start_idx < len(parts) and parts[start_idx] and 
                    len(parts[start_idx]) < 50 and not parts[start_idx].startswith('/')):
                    module_path = '/'.join(parts[start_idx:])
                    path_variants.add(module_path)
        
        # Always include original if it's reasonable (not absolute, not too long)
        if not normalized_uri.startswith('/') and len(normalized_uri) < 200:
            path_variants.add(normalized_uri)
            
        return path_variants
    
    def _extract_fixed_locations(self) -> Dict[str, Set[str]]:
        """Extract fixed methods and files for given CVE"""
        fixed_files = set()
        fixed_methods = set()
        fix_data = pd.read_csv(self.fix_data)
        
        # Filter rows for this specific CVE
        cve_rows = fix_data[fix_data['cve_id'] == self.cve_id]
        
        # Extract Java files and methods for this CVE (excluding test files)
        for file_name in cve_rows["file"]:
            if file_name.endswith(".java") and not self._is_test_file(file_name):
                fixed_files.add(file_name)
        
        # Create method keys in format "file:class:method" (excluding test files)
        for _, row in cve_rows.iterrows():
            file_name = row["file"]
            if (pd.notna(row["method"]) and pd.notna(row["class"]) and
                file_name.endswith(".java") and
                not self._is_test_file(file_name)):
                method_key = f"{file_name}:{row['class']}:{row['method']}"
                fixed_methods.add(method_key)
        
        self.logger.info(f"Extracted {len(fixed_files)} fixed files and {len(fixed_methods)} fixed methods for {self.cve_id}")
         
        return {
                "files": fixed_files,
                "methods": fixed_methods
        }
    
    
    def _load_project_structure(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Load project classes and methods using CodeQL queries with caching"""
        if not self.database_path:
            raise ValueError("Database path required to load project structure")
        
        # Determine database type and cache directory
        db_type = "vulnerable" if "vul" in self.database_path else "fixed"
        cve_dir = Path(self.database_path).parent
        cache_dir = cve_dir / f"{db_type}_project_structure"
        
        classes_cache = cache_dir / "classes.csv"
        methods_cache = cache_dir / "methods.csv"
        
        # Check if cache exists and is valid
        if classes_cache.exists() and methods_cache.exists():
            try:
                self.logger.info(f"Loading project structure from cache: {cache_dir}")
                project_classes = pd.read_csv(classes_cache)
                project_methods = pd.read_csv(methods_cache)
                self.logger.info(f"Loaded {len(project_classes)} classes and {len(project_methods)} methods from cache")
                return project_classes, project_methods
            except Exception as e:
                self.logger.warning(f"Failed to load from cache, will regenerate: {e}")
        
        # Cache doesn't exist or is invalid, run CodeQL queries
        import subprocess
        import tempfile
        
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Run class locations query
            with tempfile.NamedTemporaryFile(suffix='.bqrs', delete=False) as class_bqrs:
                class_bqrs_path = class_bqrs.name
            
            self.logger.info("Running class locations query...")
            cmd_classes = [
                "codeql", "query", "run",
                "--database", self.database_path,
                "--output", class_bqrs_path,
                f"{QUERIES_PATH}/fetch_class_locs.ql"
            ]
            
            result = subprocess.run(cmd_classes, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                self.logger.error(f"Failed to run class query: {result.stderr}")
                raise RuntimeError(f"Class query failed: {result.stderr}")
            
            # Convert to CSV
            subprocess.run([
                "codeql", "bqrs", "decode",
                "--format=csv",
                "--output", str(classes_cache),
                class_bqrs_path
            ], check=True, timeout=300)
            
            # Run method locations query  
            with tempfile.NamedTemporaryFile(suffix='.bqrs', delete=False) as method_bqrs:
                method_bqrs_path = method_bqrs.name
            
            self.logger.info("Running method locations query...")
            cmd_methods = [
                "codeql", "query", "run", 
                "--database", self.database_path,
                "--output", method_bqrs_path,
                f"{QUERIES_PATH}/fetch_func_locs.ql"
            ]
            
            result = subprocess.run(cmd_methods, capture_output=True, text=True, timeout=300)
            if result.returncode != 0:
                self.logger.error(f"Failed to run method query: {result.stderr}")
                raise RuntimeError(f"Method query failed: {result.stderr}")
            
            # Convert to CSV
            subprocess.run([
                "codeql", "bqrs", "decode",
                "--format=csv", 
                "--output", str(methods_cache),
                method_bqrs_path
            ], check=True, timeout=300)
            
            # Load DataFrames
            project_classes = pd.read_csv(classes_cache)
            project_methods = pd.read_csv(methods_cache)
            
            self.logger.info(f"Generated and cached {len(project_classes)} classes and {len(project_methods)} methods")
            
            # Cleanup temp files
            os.unlink(class_bqrs_path)
            os.unlink(method_bqrs_path)
            
            return project_classes, project_methods
            
        except Exception as e:
            self.logger.error(f"Failed to load project structure: {e}")
            raise
           
    def _parse_sarif_result(self, sarif_path: str) -> Dict:
        """Parse SARIF file and extract results"""
        try:
            with open(sarif_path, 'r') as f:
                sarif_data = json.load(f)
            
            return sarif_data
        except Exception as e:
            self.logger.error(f"Failed to parse SARIF file: {e}")
            return {}
    
    def _extract_code_flow_passing_files(self, code_flow: Dict) -> Set[str]:
        """Extract all files that a code flow passes through"""
        passing_files = set()
        
        try:
            thread_flows = code_flow.get('threadFlows', [])
            for thread_flow in thread_flows:
                locations = thread_flow.get('locations', [])
                for location in locations:
                    physical_location = location.get('location', {}).get('physicalLocation', {})
                    artifact_location = physical_location.get('artifactLocation', {})
                    uri = artifact_location.get('uri', '')
                    if uri:
                        # Generate multiple path variants to handle inconsistent path formats
                        path_variants = self._generate_sarif_path_variants(uri)
                        # Add any variant that could potentially match (intersection logic handles the rest)
                        for variant in path_variants:
                            passing_files.add(variant)
        
        except Exception as e:
            self.logger.error(f"Failed to extract passing files: {e}")
        
        return passing_files
    
    def _extract_code_flow_passing_methods(self, code_flow: Dict, database_path: Optional[str]) -> Set[str]:
        """Extract all methods that a code flow passes through"""
        passing_methods = set()
        if database_path is not None:
            self.database_path = database_path
        self.project_classes, self.project_methods = self._load_project_structure()
        
        try:
            thread_flows = code_flow.get('threadFlows', [])
            for thread_flow in thread_flows:
                locations = thread_flow.get('locations', [])
                for location in locations:
                    try:
                        physical_location = location.get('location', {}).get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        file_name = artifact_location.get('uri', '')
                        region = physical_location.get('region', {})
                        start_line = region.get('startLine')
                        
                        if not file_name or not start_line:
                            continue
                            
                        # Keep original file name for database queries (don't normalize!)
                        # Database stores full paths like "vertx-web/src/main/java/..."
                        db_file_name = file_name.replace('file://', '')

                        # Get the closest enclosing class using database file path
                        relevant_classes = self.project_classes[
                            (self.project_classes["file"] == db_file_name) &
                            (self.project_classes["start_line"] <= start_line) &
                            (self.project_classes["end_line"] >= start_line)
                        ].sort_values(by="start_line", ascending=False)
                        if len(relevant_classes) == 0: 
                            continue
                        relevant_class = relevant_classes.iloc[0]["name"]

                        # Get the closest enclosing method using database file path
                        relevant_methods = self.project_methods[
                            (self.project_methods["file"] == db_file_name) &
                            (self.project_methods["start_line"] <= start_line) &
                            (self.project_methods["end_line"] >= start_line)
                        ].sort_values(by="start_line", ascending=False)
                        if len(relevant_methods) == 0: 
                            continue
                        relevant_method = relevant_methods.iloc[0]["name"]
                        
                        # Create method keys using multiple path variants for flexible matching
                        path_variants = self._generate_sarif_path_variants(db_file_name)
                        for normalized_file_name in path_variants:
                            method_key = f"{normalized_file_name}:{relevant_class}:{relevant_method}"
                            passing_methods.add(method_key)
                        
                    except Exception as e:
                        continue
        
        except Exception as e:
            self.logger.error(f"Failed to extract passing methods: {e}")
        return passing_methods
    
    def _iter_code_flows(self, sarif_data: Dict) -> List[Tuple[int, Dict, Dict]]:
        """Iterate through all code flows in SARIF results"""
        code_flows = []
        
        try:
            runs = sarif_data.get('runs', [])
            for run in runs:
                results = run.get('results', [])
                for idx, result in enumerate(results):
                    code_flow_list = result.get('codeFlows', [])
                    for code_flow in code_flow_list:
                        code_flows.append((idx, result, code_flow))
        
        except Exception as e:
            self.logger.error(f"Failed to iterate code flows: {e}")
        
        return code_flows
    
    def _iter_result_locations(self, sarif_data: Dict) -> List[Tuple[int, Dict, Dict]]:
        """Iterate through all result locations in SARIF results (for problem queries)"""
        locations = []
        
        try:
            runs = sarif_data.get('runs', [])
            for run in runs:
                results = run.get('results', [])
                for idx, result in enumerate(results):
                    location_list = result.get('locations', [])
                    for location in location_list:
                        locations.append((idx, result, location))
        
        except Exception as e:
            self.logger.error(f"Failed to iterate result locations: {e}")
        
        return locations
    
    def _extract_location_files(self, location: Dict) -> Set[str]:
        """Extract file from a SARIF location"""
        files = set()
        
        try:
            physical_location = location.get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            uri = artifact_location.get('uri', '')
            if uri:
                # Generate multiple path variants to handle inconsistent path formats
                path_variants = self._generate_sarif_path_variants(uri)
                # Add any variant that could potentially match (intersection logic handles the rest)
                for variant in path_variants:
                    files.add(variant)
        except Exception as e:
            self.logger.error(f"Failed to extract location files: {e}")
        
        return files
    
    def _extract_location_methods(self, location: Dict, database_path: Optional[str]) -> Set[str]:
        """Extract methods from a SARIF location"""
        methods = set()
        if database_path is not None:
            self.database_path = database_path
        self.project_classes, self.project_methods = self._load_project_structure()
        
        try:
            physical_location = location.get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            file_name = artifact_location.get('uri', '')
            region = physical_location.get('region', {})
            start_line = region.get('startLine')
            
            if not file_name or not start_line:
                return methods
                
            # Keep original file name for database queries (don't normalize!)
            # Database stores full paths like "vertx-web/src/main/java/..."
            db_file_name = file_name.replace('file://', '')
            
            # Get the closest enclosing class using database file path
            relevant_classes = self.project_classes[
                (self.project_classes["file"] == db_file_name) &
                (self.project_classes["start_line"] <= start_line) &
                (self.project_classes["end_line"] >= start_line)
            ].sort_values(by="start_line", ascending=False)
            if len(relevant_classes) == 0: 
                return methods
            relevant_class = relevant_classes.iloc[0]["name"]

            # Get the closest enclosing method using database file path
            relevant_methods = self.project_methods[
                (self.project_methods["file"] == db_file_name) &
                (self.project_methods["start_line"] <= start_line) &
                (self.project_methods["end_line"] >= start_line)
            ].sort_values(by="start_line", ascending=False)
            if len(relevant_methods) == 0: 
                return methods
            relevant_method = relevant_methods.iloc[0]["name"]
            
            # Create method keys using multiple path variants for flexible matching  
            path_variants = self._generate_sarif_path_variants(db_file_name)
            for normalized_file_name in path_variants:
                method_key = f"{normalized_file_name}:{relevant_class}:{relevant_method}"
                methods.add(method_key)
            
        except Exception as e:
            self.logger.error(f"Failed to extract location methods: {e}")
        
        return methods
    
    def evaluate_sarif_result_with_locations(self, sarif_path: str, query_path: str, database_path: Optional[str]) -> Dict:
        """Evaluate SARIF results with support for both codeFlows and locations"""
        
        # Load SARIF file
        sarif_data = self._parse_sarif_result(sarif_path)
        if not sarif_data:
            return {"error": "Failed to parse SARIF file"}

        # Initialize counters
        code_flow_passes_fix_file = False
        code_flow_passes_fix_method = False
        num_true_pos_paths_file = 0
        num_true_pos_paths_method = 0
        tp_result_file_ids = set()
        tp_result_method_ids = set()
        num_total = 0
        
        # Get fixed locations
        fixed_files = self.fixed_locations["files"]
        fixed_methods = self.fixed_locations["methods"]
         
        self.logger.info(f"Evaluating against {len(fixed_files)} fixed files and {len(fixed_methods)} fixed methods")
        
        # Handle both path-problem queries (with codeFlows) and problem queries (with locations)
        all_code_flows = self._iter_code_flows(sarif_data)
        all_locations = self._iter_result_locations(sarif_data)
        
        # Process code flows (for path-problem queries)
        for (result_id, result, code_flow) in all_code_flows:
            # Get file-level recall
            passing_files = self._extract_code_flow_passing_files(code_flow)
            
            if len(fixed_files.intersection(passing_files)) > 0:
                code_flow_passes_fix_file = True
                num_true_pos_paths_file += 1
                tp_result_file_ids.add(result_id)
            
            # Get method-level recall
            passing_methods = self._extract_code_flow_passing_methods(code_flow, database_path)
            
            if len(fixed_methods.intersection(passing_methods)) > 0:
                code_flow_passes_fix_method = True
                num_true_pos_paths_method += 1
                tp_result_method_ids.add(result_id)
            
            num_total += 1
        
        # Process locations (for problem queries) - but only if no code flows exist
        # This avoids double counting for mixed queries that have both
        if len(all_code_flows) == 0:
            for (result_id, result, location) in all_locations:
                # Get file-level recall
                passing_files = self._extract_location_files(location)
                
                if len(fixed_files.intersection(passing_files)) > 0:
                    code_flow_passes_fix_file = True
                   # num_true_pos_paths_file += 1
                    tp_result_file_ids.add(result_id)
                
                # Get method-level recall
                passing_methods = self._extract_location_methods(location, database_path)
                
                if len(fixed_methods.intersection(passing_methods)) > 0:
                    code_flow_passes_fix_method = True
                   # num_true_pos_paths_method += 1
                    tp_result_method_ids.add(result_id)
                
                num_total += 1

        num_true_pos_results_file = len(tp_result_file_ids)
        num_true_pos_results_method = len(tp_result_method_ids)
        
        # Calculate metrics
        num_results = len(sarif_data.get('runs', [{}])[0].get('results', []))
        
        evaluation_result = {
            "cve_id": self.cve_id,
            "query_path": query_path,
            "num_results": num_results,
            "num_paths": num_total,
            "recall_file": code_flow_passes_fix_file,
            "num_tp_paths_file": num_true_pos_paths_file,
            "num_tp_results_file": num_true_pos_results_file,
            "recall_method": code_flow_passes_fix_method,
            "num_tp_paths_method": num_true_pos_paths_method,
            "num_tp_results_method": num_true_pos_results_method,
            "fixed_files": list(fixed_files),
            "fixed_methods": list(fixed_methods)
        }
        print("evaluation result", evaluation_result)
        with open(self.final_output_json_path, 'w') as f:
            json.dump(evaluation_result, f, indent=2)
        return evaluation_result
    
    def evaluate_sarif_result(self, sarif_path: str, query_path: str, database_path: Optional[str]) -> Dict:
        """Evaluate SARIF results against CVE fixed locations to calculate true positives"""
        
        # FEATURE TOGGLE: Use new function with location support if enabled
        if ENABLE_LOCATION_SUPPORT:
            return self.evaluate_sarif_result_with_locations(sarif_path, query_path, database_path)
        
        # Load SARIF file
        sarif_data = self._parse_sarif_result(sarif_path)
        if not sarif_data:
            return {"error": "Failed to parse SARIF file"}
        
        # Initialize counters
        code_flow_passes_fix_file = False
        code_flow_passes_fix_method = False
        num_true_pos_paths_file = 0
        num_true_pos_paths_method = 0
        tp_result_file_ids = set()
        tp_result_method_ids = set()
        num_total = 0
        
        # Get fixed locations
        fixed_files = self.fixed_locations["files"]
        fixed_methods = self.fixed_locations["methods"]
         
        self.logger.info(f"Evaluating against {len(fixed_files)} fixed files and {len(fixed_methods)} fixed methods")
        
        # Iterate through all code flows
        all_code_flows = self._iter_code_flows(sarif_data)
        
        for (result_id, result, code_flow) in all_code_flows:
            # Get file-level recall
            passing_files = self._extract_code_flow_passing_files(code_flow)
            
            if len(fixed_files.intersection(passing_files)) > 0:
                code_flow_passes_fix_file = True
                num_true_pos_paths_file += 1
                tp_result_file_ids.add(result_id)
            
            # Get method-level recall
            passing_methods = self._extract_code_flow_passing_methods(code_flow, database_path)
            
            if len(fixed_methods.intersection(passing_methods)) > 0:
                code_flow_passes_fix_method = True
                num_true_pos_paths_method += 1
                tp_result_method_ids.add(result_id)
            
            num_total += 1
        
        num_true_pos_results_file = len(tp_result_file_ids)
        num_true_pos_results_method = len(tp_result_method_ids)
        
        # Calculate metrics
        num_results = len(sarif_data.get('runs', [{}])[0].get('results', []))
        
        evaluation_result = {
            "cve_id": self.cve_id,
            "query_path": query_path,
            "num_results": num_results,
            "num_paths": num_total,
            "recall_file": code_flow_passes_fix_file,
            "num_tp_paths_file": num_true_pos_paths_file,
            "num_tp_results_file": num_true_pos_results_file,
            "recall_method": code_flow_passes_fix_method,
            "num_tp_paths_method": num_true_pos_paths_method,
            "num_tp_results_method": num_true_pos_results_method,
            "fixed_files": list(fixed_files),
            "fixed_methods": list(fixed_methods)
        }
        with open(self.final_output_json_path, 'w') as f:
            json.dump(evaluation_result, f, indent=2)
        return evaluation_result
    
    def evaluate_query(self, query_path: str, database_path: str, output_sarif_path: str) -> Dict:
        """Run CodeQL query and evaluate results"""
        import subprocess
        import tempfile
        try:
            # Generate temporary BQRS file path
            bqrs_path = output_sarif_path.replace('.sarif', '.bqrs')
            if not bqrs_path.endswith('.bqrs'):
                bqrs_path += '.bqrs'
            
            # Step 1: Run CodeQL query to generate BQRS
            self.logger.info(f"Running CodeQL query: {query_path}")
            cmd_run = [
                "codeql", "query", "run",
                "--database", database_path,
                "--output", bqrs_path,
                query_path
            ]
            
            result = subprocess.run(cmd_run, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"CodeQL query failed: {result.stderr}")
                return {"error": f"CodeQL query failed: {result.stderr}"}
            
            self.logger.info(f"Query completed, BQRS saved to: {bqrs_path}")
            
            # Step 2: Generate SARIF using database analyze
            self.logger.info("Generating SARIF format")
            cmd_analyze = [
                "codeql", "database", "analyze",
                database_path,
                query_path,
                "--format=sarif-latest",
                "--output", output_sarif_path
            ]
            
            result = subprocess.run(cmd_analyze, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"SARIF conversion failed: {result.stderr}")
                return {"error": f"SARIF conversion failed: {result.stderr}"}
            
            self.logger.info(f"SARIF output saved to: {output_sarif_path}")
            
            # Step 3: Evaluate the SARIF results
            return self.evaluate_sarif_result(output_sarif_path, query_path, database_path)
            
        except Exception as e:
            self.logger.error(f"Failed to run query evaluation: {e}")
            return {"error": str(e)}


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python evaluation.py <cve_id> <diff_file> <sarif_file>")
        sys.exit(1)
    
    cve_id = sys.argv[1]
    diff_file = sys.argv[2]
    sarif_file = sys.argv[3]
    
    evaluator = QueryEvaluator(cve_id, diff_file)
    result = evaluator.evaluate_sarif_result(sarif_file)
    
    print(json.dumps(result, indent=2))