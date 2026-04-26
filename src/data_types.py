#!/usr/bin/env python3

from dataclasses import dataclass
from typing import Optional, Any, Tuple, List

@dataclass
class VulnAnalysisTask:
    vuln_db_path: str
    fixed_db_path: str
    fix_commit_diff: str
    vulnerability_type: Optional[str] = None
    cve_id: Optional[str] = None
    cve_nist_url: Optional[str] = None
    cve_description: Optional[str] = None
    output_dir: Optional[str] = None
    working_dir: Optional[str] = None  # Current working directory for file operations
    max_iteration: Optional[int] = 1
    model: Optional[str] = "sonnet"
    ast_cache: Optional[str] = None
    nvd_cache: Optional[str] = None 

@dataclass
class IterationResult:
    """Container for single iteration results"""
    iteration_number: int
    query_path: Optional[str] = None
    compilation_summary: Optional[str] = None
    execution_summary: Optional[str] = None
    success: bool = False
    error: Optional[str] = None
    context_length: int = 0
    # Numerical results for reliable success detection
    vulnerable_results: int = 0
    fixed_results: int = 0
    compilation_successful: bool = False
    # Evaluation-based results for precise success detection
    vuln_recall_method: bool = False
    fixed_recall_method: bool = False
    vuln_tp_methods: int = 0
    fixed_tp_methods: int = 0
    vuln_num_results: int = 0
    fixed_num_results: int = 0
    # Detailed evaluation information for feedback
    vuln_eval_result: Optional[Any] = None
    fixed_eval_result: Optional[Any] = None