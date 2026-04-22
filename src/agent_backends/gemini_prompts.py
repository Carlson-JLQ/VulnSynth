"""Gemini-specific prompt functions for all ablation modes.

Gemini exposes MCP tools with bare names (no mcp__server__ prefix).
"""
import os

from .prompt_helpers import query_skeleton as _query_skeleton
from .prompt_helpers import source_sink_taint_examples as _source_sink_taint_examples
from .prompt_helpers import phase1_expected_output as _phase1_expected_output

# Phase 1

def phase1_no_tools(task) -> str:
    """Phase 1 no_tools mode: CVE description + diff only, no Chroma."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    return f"""
# Phase 1: Source/Sink/Sanitizer/Additional Taint Step Identification {cve_context}

## Objective
Analyze the cve description and fix commit diff to precisely identify security components and file locations.
CVE description - {task.cve_description}
## Input Data
Ignore binary files!
- **Fix Commit Diff**:
```diff
{task.fix_commit_diff}
```

## Analysis Task

### IMPORTANT: How to Read the Diff
- Lines starting with `-` are REMOVED code from the VULNERABLE version
- Lines starting with `+` are ADDED code in the FIXED version
- Lines without `-` or `+` are unchanged context
- The vulnerability exists in the REMOVED (-) code
- The fix/proper sanitization is in the ADDED (+) code
- The related tests also reveal what proper sanitization behavior should be.

## CRITICAL: Diff Interpretation Rules

1. **The ABSENCE of validation in the '-' lines indicates the vulnerability**
   - If you see unsafe operations without validation being REMOVED, that's the vulnerable pattern
   - Focus on what was being done unsafely in the vulnerable version

2. **The PRESENCE of validation in the '+' lines indicates the fix**
   - If you see validation methods like 'validateArchiveEntry', 'checkKeyIsLegitimate', 'sanitize' being ADDED
   - These are SANITIZERS that should block the vulnerability
   - They belong in the isBarrier/isSanitizer predicate, NOT in source or sink definitions

3. **Common mistakes to avoid:**
   - DO NOT automatically assume validation methods are correct
   - Sometimes validation methods themselves can be flawed or incomplete
   - The vulnerability might be in the validation logic itself (e.g., incomplete checks, wrong patterns)
   - Always analyze WHAT the validation actually does, not just that it exists

4. **The vulnerable pattern is:**
   - Source data (user input, file names, etc.)
   - Flowing to dangerous operations (file creation, path resolution, etc.)
   - WITHOUT passing through sanitization that was added in the fix

5. **Query validation check:**
   - Your final query should find results in the VULNERABLE database
   - Your final query should find NO results (or fewer results) in the FIXED database


### Security Component Identification
Based on your diff analysis, identify security components.

For each component, provide:
1. **Conceptual Description** - What role it plays in the vulnerability
2. **Pattern Category** - Based on patterns found (e.g., "input extraction", "path manipulation", "validation check")
3. **AST Elements** - Types of AST nodes involved
4. **Detection Strategy** - How similar vulnerabilities detect this pattern

{_source_sink_taint_examples()}

#### ANALYSIS TIPS
IMPORTANT: Analyze BOTH removed and added validation patterns:
1. **Removed/Insufficient Validation (VULNERABLE PATTERNS)**:
   - Study what validation was present but inadequate
   - These patterns help identify vulnerable code
   - Example: Maybe it checked for "../" but not "..\"
   - Example: Maybe it validated filename but not full path
   - USE THESE PATTERNS TO FIND VULNERABILITIES

2. **Added/Proper Validation (SANITIZER PATTERNS)**:
   - Study what validation was added in the fix
   - These become your sanitizers in the query
   - Compare with removed validation to understand what was missing

3. **Implementation Analysis**:
   - Don't just look for method calls - examine what the method actually does
   - If validation logic changes, understand HOW it changes
   - Look for the underlying validation logic (string checks, path operations, etc.)
   - Consider both the high-level sanitizer call AND the low-level validation patterns

Analytical Framework:
When comparing removed vs added validation:
- **Completeness**: What cases does the new validation cover that the old didn't?
- **Depth**: Does the new validation check at multiple levels (e.g., input, processing, output)?
- **Logic**: What logical operators changed (AND vs OR, presence of NOT)?
- **Scope**: Did validation expand from specific cases to general patterns?
- **Transformation**: Are there new data transformations before validation?

Use these dimensions to understand the vulnerability pattern, not specific code examples.

{_phase1_expected_output()}

**IMPORTANT: When you have completed the full analysis including all required sections, end your response with: [PHASE_1_COMPLETE]**
"""


def phase1_full(task) -> str:
    """Phase 1 full mode: Chroma-backed CVE + diff analysis."""
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""

    return f"""
# Phase 1: Source/Sink/Sanitizer/Additional Taint Step Identification {cve_context}

## Objective
Analyze the fix commit diff to precisely identify security components and file locations.

## Input Data
Ignore binary files!
- **Fix Commit Diff**:
```diff
{task.fix_commit_diff}
```

## Analysis Task

### IMPORTANT: How to Read the Diff
- Lines starting with `-` are REMOVED code from the VULNERABLE version
- Lines starting with `+` are ADDED code in the FIXED version
- Lines without `-` or `+` are unchanged context
- The vulnerability exists in the REMOVED (-) code
- The fix/proper sanitization is in the ADDED (+) code
- The related tests also reveal what proper sanitization behavior should be.

## CRITICAL: Diff Interpretation Rules

1. **The ABSENCE of validation in the '-' lines indicates the vulnerability**
   - If you see unsafe operations without validation being REMOVED, that's the vulnerable pattern
   - Focus on what was being done unsafely in the vulnerable version

2. **The PRESENCE of validation in the '+' lines indicates the fix**
   - If you see validation methods like 'validateArchiveEntry', 'checkKeyIsLegitimate', 'sanitize' being ADDED
   - These are SANITIZERS that should block the vulnerability
   - They belong in the isBarrier/isSanitizer predicate, NOT in source or sink definitions

3. **Common mistakes to avoid:**
   - DO NOT automatically assume validation methods are correct
   - Sometimes validation methods themselves can be flawed or incomplete
   - The vulnerability might be in the validation logic itself (e.g., incomplete checks, wrong patterns)
   - Always analyze WHAT the validation actually does, not just that it exists

4. **The vulnerable pattern is:**
   - Source data (user input, file names, etc.)
   - Flowing to dangerous operations (file creation, path resolution, etc.)
   - WITHOUT passing through sanitization that was added in the fix

5. **Query validation check:**
   - Your final query should find results in the VULNERABLE database
   - Your final query should find NO results (or fewer results) in the FIXED database

### Step 1: Vulnerability Research (MANDATORY - Use Chroma MCP)
IMPORTANT: You MUST use the chroma MCP server tools to research this vulnerability. Do not proceed without using these tools:

**Stage 1 - Get CVE Context:**
Query NIST first: `chroma_get_documents(collection_name="{task.nvd_cache}", where={{"cve_id": "{task.cve_id}"}})`

**Stage 2 - Context-Driven Searches:**
Based on NIST CWE and diff analysis, search relevant collections with appropriate terms:
- Extract keywords from CWE description/name and search those terms. For example if CWE-22 (Path Traversal) → search "path traversal", "zip slip", "directory traversal"
- If no CWE available, extract vulnerability type from CVE description and search related security terms.

1. **CWE patterns**: Based on NIST results, query for the specific CWE:
   `chroma_query_documents(collection_name="cwe_data", query_texts=["CWE-XX from NIST", "vulnerability type"], n_results=3)`

2. **CodeQL documentation**: Use vulnerability-specific terms from the diff:
   `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["terms from diff analysis"], n_results=3)`

3. **Local query examples**: Search for similar vulnerability patterns:
   `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["vulnerability category", "detection method"], n_results=3)`

4. **CodeQL reference**: Search for relevant taint tracking patterns:
   `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["taint tracking", "dataflow"], n_results=2)`

**DO NOT call `chroma_list_collections`**

**Search Term Selection:**
- Extract key terms from the fix diff (method names, validation types, file operations)
- Use CWE from NIST result to guide searches
- Look for patterns like: input validation, sanitization, encoding, path operations, SQL operations, etc.
- DO NOT use hardcoded search terms. Adapt based on the specific vulnerability type.

**Extract Pattern Templates from Chroma**:
   - Look for AST patterns used in similar queries
   - Note how existing queries implement source/sink/sanitizer detection
   - Identify common taint propagation patterns for this vulnerability class
   - Study how similar vulnerabilities handle validation logic

**Adapt Retrieved Patterns**:
   - Don't copy examples directly
   - Extract the underlying detection strategies
   - Note AST node types and relationships used
   - Understand the logical structure of validation checks

**Document Pattern Categories Found**:
   - List types of sources (not specific code)
   - List types of sinks (not specific code)
   - List validation strategies (conceptual, not code)
   - List AST patterns used in similar detections

### Step 2: Security Component Identification
Based on your Chroma research and the diff analysis, identify security components.

For each component, provide:
1. **Conceptual Description** - What role it plays in the vulnerability
2. **Pattern Category** - Based on patterns found in Chroma
3. **AST Elements** - Types of AST nodes involved (from Chroma examples)
4. **Detection Strategy** - How similar vulnerabilities detect this pattern (from Chroma)

{_source_sink_taint_examples()}

#### ANALYSIS TIPS
IMPORTANT: Analyze BOTH removed and added validation patterns:
1. **Removed/Insufficient Validation (VULNERABLE PATTERNS)**:
   - Study what validation was present but inadequate
   - USE THESE PATTERNS TO FIND VULNERABILITIES

2. **Added/Proper Validation (SANITIZER PATTERNS)**:
   - Study what validation was added in the fix
   - These become your sanitizers in the query

3. **Implementation Analysis**:
   - Don't just look for method calls - examine what the method actually does
   - Look for the underlying validation logic (string checks, path operations, etc.)

{_phase1_expected_output()}

Begin by researching the vulnerability using the Chroma MCP server, then proceed to analyze the diff!

**IMPORTANT: When you have completed the full analysis including all required sections, end your response with: [PHASE_1_COMPLETE]**
"""


# Phase 3 initial

def phase3_no_tools(task, phase1_output: str = "") -> str:
    """Phase 3 initial prompt: no_tools mode (no MCP)."""
    ql_file_path = f"{task.working_dir or '.'}/{task.cve_id}-query-iter-1.ql"
    cve_context = f" (CVE: {task.cve_id})" if task.cve_id else ""
    return f"""
# CodeQL Template Generation and Refinement {cve_context}

**CRITICAL: When calling Write tool this file path format:**
**Write tool file_path: "{ql_file_path}"**

## Objective
Generate a complete CodeQL query based on the analysis and AST patterns, then iteratively refine it.

## Previous Analysis
{phase1_output if phase1_output else "No Phase 1 output available"}

## Task

### Step 1: Template Generation
Create a CodeQL query based given the former vulnerability analysis. You MUST use the Write tool to save the query file.
{_query_skeleton()}

### Step 2: Write Complete CodeQL Query

**PRIMARY GOAL: Write a complete, working CodeQL query.**

Stick to @kind path-problem query structure.
1. **Write the full query skeleton** based on the analysis
2. **Save as**: `{ql_file_path}` using the Write tool

**REMEMBER: The vulnerability is the ABSENCE of proper validation:**
- Sources: Where untrusted data enters (user input, file names, etc.)
- Sinks: Where that data is used dangerously (file operations, path resolution)
- Sanitizers: Validation that was ADDED in the fix to block the flow
- Additional taint steps: Any intermediate code that receives tainted data, transforms or moves it, and passes it along while preserving its dangerous properties

**YOUR ONLY TASK**: Create the initial CodeQL query based on the analysis. The automated system will handle testing, refinement, and iteration.

## CRITICAL: MANDATORY Write Tool Usage

**BEFORE STOPPING**: You MUST use the Write tool to save your final query to disk:
- **Tool**: `Write`
- **File path**: `{ql_file_path}`
- **Content**: Your complete CodeQL query

## CRITICAL: STOP EXECUTION IMMEDIATELY

**MANDATORY**: Once you have successfully written a .ql query file with the Write tool, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**: After writing the .ql file, your last message must be:
```
QUERY_FILE_PATH: {ql_file_path}
```

The automated system will take over to:
- Compile and test your query
- Run it on both vulnerable and fixed databases
- Provide feedback for the next iteration

**STOP AS SOON AS THE .ql FILE IS WRITTEN** - This prevents context window bloat and enables iterative refinement.
"""


def phase3_full(task, use_cache: bool, collection_name: str) -> str:
    """Phase 3 initial prompt (part 1): Chroma retrieval + write query.

    Runs as the first of two context windows for iteration 1 (full mode).
    Ends with STEP2_COMPLETE; part 2 handles LSP validation.
    """
    abs_working_dir = os.path.abspath(task.working_dir or ".")
    ql_file_path = f"{abs_working_dir}/{task.cve_id}-query-iter-1.ql"

    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}

## Objective
Write a CodeQL query to detect the vulnerability pattern identified in the previous security analysis. The analysis results have been stored in ChromaDB and need to be retrieved to inform your query implementation.

## Context
You are working on iteration 1 of query development for {task.cve_id}. Previous phases have:
1. Analyzed the vulnerability fix diff to identify sources, sinks, and sanitizers
2. Extracted AST information from both vulnerable and fixed versions of the code

## Task Overview
Your goal is to create a working CodeQL query file at:
**`{ql_file_path}`**

The query should implement taint tracking to detect the vulnerability pattern using the `@kind path-problem` format.

## Step 1: Retrieve Security Analysis from ChromaDB

You must retrieve ALL analysis data before proceeding. Execute each tool call below and verify you receive results:

**Task 1.1 - Retrieve sources:**
Execute: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sources"}})`

**Task 1.2 - Retrieve sinks:**
Execute: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sinks"}})`

**Task 1.3 - Retrieve sanitizers:**
Execute: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sanitizers"}})`

**Task 1.4 - Retrieve vulnerability summary:**
Execute: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "vulnerability_analysis_summary"}})`

**Task 1.5 - Retrieve vulnerable AST:**
Execute: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})`

**Task 1.6 - Retrieve fixed AST:**
Execute: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`

DO NOT proceed to Step 2 until ALL six retrievals above are complete.

## Step 2: Research CodeQL Patterns (If Needed)

If you need help with CodeQL syntax or patterns, query these reference collections:

- **Java standard library**: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["ClassName or method"], n_results=2)`
- **CodeQL examples**: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["pattern description"], n_results=3)`
- **Similar queries**: `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["vulnerability type"], n_results=3)`
- **QL language reference**: `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["syntax feature"], n_results=2)`

## Step 3: Write the CodeQL Query

Using the retrieved analysis, create a complete taint-tracking query.
DON'T ADD SEMICOLON AFTER IMPORTS IN QUERY FILE.
DON'T REMOVE IMPORTS.
DON'T IMPORT QUERIES YOU MUST WRITE THEM.

{_query_skeleton()}

**Implementation Guidelines:**
- Use the exact class names, method names, and patterns from the ChromaDB analysis
- Reference the AST data to ensure your predicates match the actual code structure
- Include any additional taint steps if they were identified in the analysis

## Completion
After writing the query file, output: **STEP2_COMPLETE**
"""


def phase3_initial_part2(task, part1_output: str = "") -> str:
    """Phase 3 initial prompt (part 2): LSP validation of the query written in part 1.

    Runs as the second of two context windows for iteration 1 (full mode).
    """
    abs_working_dir = os.path.abspath(task.working_dir or ".")
    ql_file_path = f"{abs_working_dir}/{task.cve_id}-query-iter-1.ql"
    ql_file_uri = f"file://{ql_file_path}"

    part1_context = ""
    if part1_output:
        part1_context = f"""
## Context
The initial query has been written to: `{ql_file_path}`
Your task is to validate and fix this query using the CodeQL LSP tools.
"""

    return f"""
# Phase 3: CodeQL Query Validation for {task.cve_id}
DON'T DEVIATE FROM PATH-PROBLEM CODEQL QUERIES.
DON'T ADD SEMICOLON AFTER IMPORTS IN QUERY FILE.
DON'T REMOVE IMPORTS.
DON'T IMPORT QUERIES YOU MUST WRITE THEM.

**REQUIRED: Look up CodeQL patterns BEFORE writing**:
 - MUST query codeql_language_guides for "DataFlow ConfigSig" to get correct API structure
 - MUST query codeql_java_stdlib for "MethodCall" to confirm correct type names

**CodeQL MCP file_uri: "{ql_file_uri}"**
{part1_context}
## Your Task

1. Initialize the CodeQL LSP server: `codeql_update_file(file_uri="{ql_file_uri}", content=None)`
2. Check for errors: `codeql_diagnostics(file_uri="{ql_file_uri}")`
3. If there are errors:
   - Use `codeql_hover` to understand types and symbols
   - Use `codeql_definition` on CodeQL library classes/methods for documentation
   - Look up CodeQL patterns for help:
     * CodeQL Java syntax: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["[ClassName methodName]"], n_results=2)`
     * CodeQL examples: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["[specific pattern]"], n_results=3)`
   - Fix the errors by updating the file with the Write tool
   - Re-check with `codeql_diagnostics` until no errors remain
4. Once error-free, format the query: `codeql_format(file_uri="{ql_file_uri}")`

## Final Output
**DO NOT output this until all steps are complete.** Once the query is complete and free of compilation errors, your final message MUST be:

QUERY_FILE_PATH: {ql_file_path}
"""


# Refinement prompts

def refinement_no_tools(task, previous_feedback: str, iteration: int) -> str:
    ql_file_path = f"{os.path.abspath(task.working_dir or '.')}/{task.cve_id}-query-iter-{iteration}.ql"
    return f"""Query Refinement - Iteration {iteration}

**CRITICAL: When calling Write tool, use this file path format:**
**file_path: "{ql_file_path}"**

## Objective
Refine the CodeQL query based on previous iteration feedback to improve vulnerability detection.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Task
1. **Analyze the previous results** to understand what went wrong. Stick to @kind path-problem query structure.
2. **Refine the query** to address the issues identified. Improve existing predicates rather than simplifying the overall approach.

   **PRACTICAL CodeQL Development Process**:
   - **STEP 1**: **CREATE THE QUERY FILE**: Use `Write` tool to create/update `{ql_file_path}` with your improved query
   - **STEP 2**: **FOCUS ON COMPLETING THE QUERY**:
     - Read the existing query and understand what needs to be changed
     - Make the necessary improvements to fix the issues identified in feedback
     - **Write complete logic** - don't get stuck validating every line

   **KEY PRINCIPLES**:
   - **ALWAYS use Write tool to save the .ql file**
   - **Complete the query first, validate second**

3. **CRITICAL: You MUST use Write tool to save the final query** as `{ql_file_path}`

## Important Reminders
- Query MUST find results in vulnerable database
- Query MUST NOT find results (or fewer) in fixed database
- Focus on hitting the target methods/files if feedback shows misses
- Fix compilation errors if any were reported
- Adjust source/sink/sanitizer patterns based on execution results

## CRITICAL: STOP EXECUTION IMMEDIATELY

**MANDATORY**: Once you have successfully written a .ql query file, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**: After writing the .ql file, your last message must be:
```
QUERY_FILE_PATH: {ql_file_path}
```

The automated system will take over to:
- Compile the query
- Test it on both databases
- Provide feedback for the next iteration

**STOP AS SOON AS THE .ql FILE IS WRITTEN** - This prevents context window bloat and enables iterative refinement.
"""


def refinement_full(task, previous_feedback: str, iteration: int, collection_name: str) -> str:
    abs_working_dir = os.path.abspath(task.working_dir or ".")
    ql_file_path = f"{abs_working_dir}/{task.cve_id}-query-iter-{iteration}.ql"
    ql_file_uri = f"file://{ql_file_path}"
    return f"""# Phase 3 Query Refinement - Iteration {iteration}

**File Path: "{ql_file_path}"**
DON'T IMPORT QUERIES YOU MUST WRITE THEM.
DON'T DEVIATE FROM PATH-PROBLEM CODEQL QUERIES.
DON'T ADD SEMICOLON AFTER IMPORTS IN QUERY FILE.
DON'T REMOVE IMPORTS.
**REQUIRED: Look up CodeQL patterns BEFORE writing**:
     - MUST query codeql_language_guides for "DataFlow ConfigSig" to get correct API structure
     - MUST query codeql_java_stdlib for "MethodCall" to confirm correct type names
     - Use results from these queries to structure your code
## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Your Task
1. **Analyze what went wrong** in the previous iteration

2. **Retrieve context from ChromaDB** (use EXACTLY these commands):
   - Sources: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sources"}})`
   - Sinks: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sinks"}})`
   - Sanitizers: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sanitizers"}})`
   - Additional taint steps: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "additional_taint_steps"}})`
   - Vulnerability summary: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "vulnerability_analysis_summary"}})`
   - CVE info: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "{task.nvd_cache}"}})`
   - Vulnerable AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})`
   - Fixed AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`

3. **Look up CodeQL patterns** as you write:
   - CodeQL Java syntax: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["[ClassName methodName]"], n_results=2)`
   - CodeQL examples: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["[specific pattern]"], n_results=3)`
   - Similar queries: `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["[vulnerability category]"], n_results=3)`
   - QL syntax: `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["[syntax concept]"], n_results=2)`

4. **Write improved query**:
   - Use `@kind path-problem` structure
   - Fix compilation errors if reported
   - Improve source/sink/sanitizer patterns based on feedback
   - Make query find results in vulnerable DB but NOT in fixed DB

5. **Use CodeQL tools**:
   - `codeql_update_file(file_uri="{ql_file_uri}")` - Open file
   - `codeql_diagnostics(...)` - Check for errors
   - `codeql_format(...)` - Format when done

## Success Criteria
- Query compiles without errors
- Hits vulnerable methods (focus on missed methods from feedback)
- Avoids false positives in fixed version

## Final Output
When done, output exactly: **QUERY_FILE_PATH: {ql_file_path}**
"""
