"""Codex-specific prompt functions for all ablation modes.

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

**Use the direct queries above to search for:
   - The specific CVE ID
   - Related CWE patterns and their CodeQL implementations
   - Similar vulnerability types and their detection patterns
   - Existing CodeQL queries that detect similar issues
   
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

IMPORTANT: Reference pattern types from Chroma, don't create new examples. Say things like:
- "This follows the same pattern as CWE-22 detection in Chroma where..."
- "Similar to the validation strategy seen in query X from Chroma..."
- "Uses AST patterns like those in Chroma's path traversal queries..." 

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
   
### Expected Output Format
Please provide the analysis in this structured format:

```
## Vulnerability Research Summary
[Summary of findings from Chroma database research about this vulnerability type]

## CVE Information (if available)
[Summary of information from NIST CVE database]

## Relevant Files
[List ONLY the Java files that are directly related to the vulnerability including test files.]
- [filename.java] - [Brief description of why this file is relevant]
- [filename2.java] - [Brief description of why this file is relevant]

## Sources
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Sinks
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Sanitizers
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Additional Taint Steps
1. [Description]
   - File: [filename]
   - Location: [line numbers or code context]
   - Pattern: [what to look for in CodeQL]

## Vulnerability Summary
[Brief description of the vulnerability pattern and how the fix addresses it]
```

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

## Expected Output
**ONLY CREATE THE INITIAL CODEQL QUERY** - Do not run it, test it, or refine it. Just create it and stop.

Focus on creating a query that accurately detects the vulnerability pattern while minimizing false positives!

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


# Plan Agent (IR synthesis)

def plan_ir_generation(task) -> str:
    """Generate a prompt for synthesizing L1/L2/L3 IR artifacts from CVE inputs.

    The agent must output STRICT JSON (no markdown) with keys: l1, l2, l3.
    """
    # Keep diff bounded to avoid hitting context limits.
    diff_text = getattr(task, "fix_commit_diff", "") or ""
    if len(diff_text) > 120_000:
        diff_text = diff_text[:120_000] + "\n\n[TRUNCATED_DIFF]\n"

    cwe_id = getattr(task, "cwe_id", "") or ""
    cwe_name = getattr(task, "cwe_name", "") or ""
    repo_path = getattr(task, "repo_path", "") or ""
    repo_name = getattr(task, "repo_name", "") or ""
    github_url = getattr(task, "github_url", "") or ""
    buggy_commit = getattr(task, "buggy_commit_id", "") or ""
    fix_commit = getattr(task, "fix_commit_id", "") or ""

    template = """
你是 VulnSynth 的 Plan Agent。你的输入是一个 CVE case 的上下文（CVE 元数据 + CWE 信息 + 修复 diff + 本地仓库路径）。
你的任务是：
1) 产出 L1（事实层）JSON：只包含可观察事实与证据，不做推理结论；
2) 产出 L2（语义层）JSON：从 L1 抽象出漏洞语义，选择 pattern_type，并建模 entities/relations/constraints/guards/evidence/reporting；
3) 产出 L3（逻辑计划层）JSON：用 DAG steps 描述如何在代码中验证 L2 的语义（backend-independent，不能写 CodeQL 代码）。

输出要求（非常重要）：
- 仅输出一个 JSON 对象（不要 markdown、不要解释文字、不要代码块）。
- JSON 顶层必须包含三个键："l1"、"l2"、"l3"，分别是三个层的完整对象。
- 每个对象必须带上 layer/version/case_id 等字段（见下方规范）。

====================
L1 定义（Vulnerability Fact Layer）
====================
形式化：L1 = (M, C, D, E)，fact f = (id, kind, subject, proposition, evidence)

L1 JSON 规范（必须字段）：
{
  "layer": "L1_fact",
  "fact_version": "1.0",
  "case_id": "CVE-...",
  "metadata": {
    "cve_id": "...",
    "project": "...",
    "language": "...",
    "cwe": ["CWE-.."],
    "repo_name": "...",
    "github_url": "...",
    "buggy_commit_id": "...",
    "fix_commit_id": "...",
    "local_repo_path": "...",
    "diff_path": "..."
  },
  "code_facts": [f...],
  "patch_facts": [f...],
  "environment_facts": [f...]
}

其中每条 fact 建议结构：
{
  "id": "f1",
  "kind": "code_fact|patch_fact|env_fact",
  "subject": "symbol_or_file_or_api",
  "proposition": "可验证陈述句",
  "evidence": {
    "type": "diff_hunk|file_snippet|commit",
    "file": "path",
    "commit": "sha",
    "snippet": "可选，短片段",
    "lines_hint": "可选"
  }
}

L1 不允许：
- 不要出现 DataFlow/TaintTracking/CodeQL 谓词等后端实现术语。
- 不要直接下结论“漏洞成立/不成立”，只记录事实。

====================
L2 定义（Semantic Schema IR Layer）
====================
形式化：L2 = (T, Ent, Rel, Con, G, Env, Ev, Rep)

L2 JSON 规范（必须字段）：
{
  "layer": "L2_schema_ir",
  "schema_version": "2.0",
  "case_id": "CVE-...",
  "pattern_type": "taint_flow|missing_validation|incomplete_security_policy|unsafe_default|authorization_bypass|state_or_lifecycle_violation",
  "entities": [{"id":"...","kind":"...","attrs":{...}}],
  "relations": [{"id":"...","type":"...","src":"entity_id","dst":"entity_id","attrs":{...}}],
  "constraints": [{"id":"...","kind":"...","target":"entity_id","params":{...}}],
  "guards": [{"id":"...","kind":"...","target":"entity_id","params":{...}}],
  "environment_conditions": [ ... ],
  "evidence": [ ... ],
  "reporting": { ... }
}

实体 kind（受控词表建议）：
input, subject, policy, policy_member, check, action, config_key, config_value, constant, api_call, api_result, container, transform, sanitizer, guard_value

关系 type（受控词表建议）：
reads_from, derived_from, flows_to, checks, protects, uses_policy, contains_member, missing_member, compares_against, controls, blocks, allows, normalizes, validates, aliases

L2 的关键不变量：
- L2 不包含可执行 CodeQL 代码。
- L2 的每个关键语义对象（尤其 constraints/guards）要能追溯到 L1 的 evidence（通过 L2.evidence.supports 链接）。

====================
L3 定义（Logic Plan IR Layer）
====================
形式化：L3 = (Goal, Steps, Dep)，step = (id, kind, In, Out, Op, Crit, Fail)

L3 JSON 规范（必须字段）：
{
  "layer": "L3_logic_plan",
  "plan_version": "1.0",
  "case_id": "CVE-...",
  "goal": "prove violation of L2 constraints",
  "steps": [
    {
      "id": "s1...",
      "kind": "locate|bind|derive|relate|constrain|exclude|report",
      "intent": "...",
      "inputs": ["symbol_or_entity_id"],
      "outputs": ["symbol_or_entity_id"],
      "depends_on": ["step_id"],
      "operation": {
        "type": "symbolic_operation_type",
        "selector": { ... },
        "filters": [ ... ],
        "join_conditions": [ ... ]
      },
      "success_criterion": "...",
      "failure_mode": "...",
      "retrieval_hints": {
        "stdlib_predicates": ["要检索的标准库谓词/概念"],
        "similar_query_features": {"keywords":[],"apis":[],"packages":[]}
      },
      "lowering_target": {"kind": "binding_predicate|analysis_view_mapping|value_constraint_predicate|select_template", "name_suggestion": "..."}
    }
  ]
}

L3 不允许：
- 不能直接写 CodeQL 代码片段（只能写 selector/锚点/检索提示）。
- steps 之间必须构成 DAG（depends_on 不成环）。

====================
示例（仅示意结构，不要照抄内容）
====================
示例输出顶层：
{
  "l1": {"layer":"L1_fact", "fact_version":"1.0", "case_id":"...", "metadata":{...}, "code_facts":[], "patch_facts":[], "environment_facts":[]},
  "l2": {"layer":"L2_schema_ir", "schema_version":"2.0", "case_id":"...", "pattern_type":"...", "entities":[], "relations":[], "constraints":[], "guards":[], "environment_conditions":[], "evidence":[], "reporting":{...}},
  "l3": {"layer":"L3_logic_plan", "plan_version":"1.0", "case_id":"...", "goal":"...", "steps":[]}
}

====================
当前 case 输入
====================
CVE: <<CVE_ID>>
Repo: <<REPO_NAME>>
GitHub: <<GITHUB_URL>>
Local repo path (under cves/): <<REPO_PATH>>
CWE: <<CWE_ID>> <<CWE_NAME>>
Buggy commit: <<BUGGY_COMMIT>>
Fix commit: <<FIX_COMMIT>>

Fix commit diff:
<<DIFF_TEXT>>

现在开始：严格按规范输出一个 JSON（仅 JSON）。
"""

    return (
        template
        .replace("<<CVE_ID>>", str(getattr(task, "cve_id", "") or ""))
        .replace("<<REPO_NAME>>", repo_name)
        .replace("<<GITHUB_URL>>", github_url)
        .replace("<<REPO_PATH>>", repo_path)
        .replace("<<CWE_ID>>", cwe_id)
        .replace("<<CWE_NAME>>", cwe_name)
        .replace("<<BUGGY_COMMIT>>", buggy_commit)
        .replace("<<FIX_COMMIT>>", fix_commit)
        .replace("<<DIFF_TEXT>>", diff_text)
    )



def phase3_full(task, use_cache: bool, collection_name: str) -> str:
    """Phase 3 initial prompt: full mode with Chroma + CodeQL LSP.

    """
    abs_working_dir = os.path.abspath(task.working_dir or ".")
    ql_file_path = f"{abs_working_dir}/{task.cve_id}-query-iter-1.ql"
    ql_file_uri = f"file://{ql_file_path}"
    if use_cache and collection_name:
        previous_analysis_section = f"""
## Previous Analysis
The results from Phase 1 Chroma in a run-specific collection.

**Collection Name:** `{collection_name}`

**IMPORTANT**: 
- Only access data from collection `{collection_name}`

### Retrieving Phase 1 Results:
Use `chroma_get_documents` with collection_name="{collection_name}" and:
- `where: {{"section": "sources"}}` - Source patterns
- `where: {{"section": "sinks"}}` - Sink patterns
- `where: {{"section": "sanitizers"}}` - Sanitizer patterns
- `where: {{"section": "additional_taint_steps"}} - Additional taint step patterns
- `where: {{"section": "vulnerability_anaylsis_summary"}}` - Vulnerability analysis summary
- `where: {{"section": "cve_info"}}` - CVE information from NIST

Example:
```
chroma_get_documents(
    collection_name="{collection_name}",
    where={{"section": "vulnerable_ast"}},
    limit=1
)
```
"""
    return f"""
# Phase 3: CodeQL Query Generation for {task.cve_id}

## Objective
Write a CodeQL query to detect the vulnerability pattern identified in the previous security analysis. The analysis results have been stored in ChromaDB and need to be retrieved to inform your query implementation.
{previous_analysis_section}

**CRITICAL: When calling Write tool and CodeQL MCP tools, use these file path formats:**
**Write tool file_path: "{task.working_dir or '.'}/{task.cve_id}-query-iter-1.ql"**
**CodeQL MCP file_uri: "file://{task.working_dir or '.'}/{task.cve_id}-query-iter-1.ql"**
**Use the FULL ABSOLUTE PATH to ensure the file can be found by CodeQL MCP tools.**

## Objective
Generate a complete CodeQL query based on the analysis and AST patterns, then iteratively refine it.
{previous_analysis_section}

## Task
Using the Chroma MCP server for documentation and CodeQL query examples, and CodeQL MCP server for CodeQL development:

### Step 1: MANDATORY AST Retrieval and Comparison
**BEFORE generating any CodeQL query, you MUST:**
1. Retrieve the vulnerable AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})` 
2. Retrieve the fixed AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`
3. Compare the AST structures to identify:
   - What patterns exist in vulnerable code but NOT in fixed code
   - What new patterns were added in the fixed code
   - The exact AST node types and relationships that changed
4. Use this comparison to inform your source, sink, and sanitizer definitions

## Step 2: Query Template Generation 
Create a CodeQL query based on the AST comparison analysis. Look up similar existing queries from the allowed reference collections (cwe_data, codeql_language_guides, codeql_local_queries, codeql_ql_reference, codeql_java_stdlib) - DO NOT search cve_analysis_* collections:

{_query_skeleton()}

### CRITICAL: Initial Syntax Check and CodeQL Development Process
**IMMEDIATELY after writing the initial query above:**
1. Save the query as a .ql file using the Write tool
2. **MANDATORY**: Use `codeql_update_file` to open it with the CodeQL LSP
3. **MANDATORY**: Use `codeql_diagnostics` to check for syntax errors and compilation issues
4. **IF ANY ERRORS**: Fix syntax errors using CodeQL MCP tools:
   - Use `codeql_hover` to understand types and methods
   - Use `codeql_complete` for syntax suggestions  
   - Use `codeql_format` to format the query properly
5. **MANDATORY**: Re-run `codeql_diagnostics` after fixes until clean
6. **MANDATORY**: Use `codeql_format` to ensure proper formatting

### Step 3: Create Initial CodeQL Query
1. **Before writing any CodeQL**: Use `codeql_update_file`
2. **During development**: ACTIVELY use CodeQL MCP tools:
   - **MANDATORY**: `codeql_diagnostics` after writing each predicate to catch errors early
   - **MANDATORY**: `codeql_hover` to understand return types and method signatures
   - **MANDATORY**: `codeql_complete` when writing complex expressions
   - **MANDATORY**: `codeql_format` to ensure proper code formatting
3. **For implementation guidance**: Look up patterns as you write:
   - **CodeQL Java syntax**: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["[ClassName methodName]"], n_results=2)`
   - **CodeQL examples**: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["[specific pattern]"], n_results=3)`
   - **Similar queries**: `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["[vulnerability category]"], n_results=3)`
   - **QL syntax**: `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["[syntax concept]"], n_results=2)`
4. **Create the query**: Use `codeql_update_file` to open the .ql file with the LSP
5. **CRITICAL**: Use `codeql_diagnostics` to check for compilation errors and warnings
6. **Fix all issues**: Use the MCP tools to resolve any problems before finishing
7. **Final check**: Use `codeql_format` to ensure clean formatting

**THESE TOOLS ARE ESSENTIAL - they provide real-time CodeQL validation and prevent common errors**

**REMEMBER: The vulnerability is the ABSENCE of proper validation:**
- Sources: Where untrusted data enters (user input, file names, etc.)
- Sinks: Where that data is used dangerously (file operations, path resolution)
- Sanitizers: Validation that was ADDED in the fix to block the flow
- Additional taint steps: Any intermediate code that receives tainted data, transforms or moves it, and passes it along while preserving its dangerous properties

### Expected Output
**ONLY CREATE THE INITIAL CODEQL QUERY** - Do not run it, test it, or refine it. Just create it and stop.

Focus on creating a query that accurately detects the vulnerability pattern while minimizing false positives!

## CRITICAL: STOP EXECUTION IMMEDIATELY 
**IMPORTANT**: LSP tools only update the in-memory representation. The Write tool is required to persist the file to disk for the automated system to find it.
**MANDATORY**: Once you have successfully written a .ql query file, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**: After writing the .ql file, your last message must be:
```
QUERY_FILE_PATH: [exact file path you used in Write tool]
```

**STOP AS SOON AS THE .ql FILE IS WRITTEN** - This prevents context window bloat and enables iterative refinement.
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
   - **File path**: `{task.cve_id}-query-iter-{iteration}.ql` (NOT "/path/to/{task.cve_id}-query-{iteration}.ql")

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

**CRITICAL: When calling Write tool and CodeQL MCP tools, use these file path formats:**
**Write tool file_path: "{task.working_dir or '.'}/{task.cve_id}-query-iter-{iteration}.ql"**
**CodeQL MCP file_uri: "file://{task.working_dir or '.'}/{task.cve_id}-query-iter-{iteration}.ql"**
**Use the FULL ABSOLUTE PATH to ensure the file can be found by CodeQL MCP tools.**

## Objective
Refine the CodeQL query based on previous iteration feedback to improve vulnerability detection.

## Previous Iteration Feedback
{previous_feedback or "No previous feedback available"}

## Collection Name: `{collection_name}`

## Your Task
1. **Analyze what went wrong** in the previous iteration

2. **Retrieve context from ChromaDB** (use EXACTLY these commands):
   - Sources: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sources"}})`
   - Sinks: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sinks"}})`
   - Sanitizers: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "sanitizers"}})`
   - Additional taint steps: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "additional_taint_steps"}})`
   - Vulnerability summary: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "vulnerability_analysis_summary"}})`
   - CVE info: `chroma_get_documents(collection_name="{collection_name}", where={{"section": "cve_info"}})`
   - Vulnerable AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "vulnerable"}}]}})`
   - Fixed AST: `chroma_get_documents(collection_name="{task.ast_cache}", where={{"$and": [{{"cve_id": "{task.cve_id}"}}, {{"db_type": "fixed"}}]}})`

3. **Refine the query** to address the issues identified. Improve existing predicates rather than simplifying the overall approach. Each refinement should make the analysis more accurate, not simpler.
   ** PRACTICAL CodeQL Development Process**:
   - **STEP 1**: **CREATE THE QUERY FILE**: Use `Write` tool to create/update `{task.cve_id}-query-iter-{iteration}.ql` with your improved query
   - **STEP 2**: **VALIDATE WITH LSP (Optional)**: 
     - Open with LSP: `codeql_update_file` (for validation only, NOT file creation)
     - Check errors: `codeql_diagnostics`
     - **IF ERRORS**: Use `codeql_hover`, `codeql_complete` for help, then **update with Write tool again**
     - Format: `codeql_format` (optional)
   - **STEP 3**: **FOCUS ON COMPLETING THE QUERY**:
     - Read the existing query and understand what needs to be changed
     - Make the necessary improvements to fix the issues identified in feedback
     - **Write complete logic** - don't get stuck validating every line
   - **STEP 4**: **USE LSP TOOLS FOR HELP (Not File Creation)**:
     - **When you need help**: Use `codeql_complete` for auto-completion
     - **When confused**: Use `codeql_hover` on elements for documentation
     - **For library methods**: Use `codeql_definition` on CodeQL library types (like `MethodCall`, `TryStmt`) - NOT on user variables
     - **For examples**: Use `codeql_references` on library predicates or `chroma_query_documents`

   ** KEY PRINCIPLES**:
   - **ALWAYS use Write tool to save the .ql file** - LSP tools only validate, they don't save files
   - **Complete the query first, validate second**
   - **Use tools when helpful, not as mandatory checkpoints** 
   - **`definition` works on**: CodeQL library classes/methods (e.g., `TryStmt`, `MethodCall`, `getMethod()`)
   - **`definition` doesn't work on**: imports, user variables, keywords
   - **Don't let tool usage block query completion**
   - **For implementation guidance**: Actively look up patterns as you write:
     - CodeQL Java syntax: `chroma_query_documents(collection_name="codeql_java_stdlib", query_texts=["[ClassName methodName]"], n_results=2)`
     - CodeQL examples: `chroma_query_documents(collection_name="codeql_language_guides", query_texts=["[specific pattern]"], n_results=3)`
     - Similar queries: `chroma_query_documents(collection_name="codeql_local_queries", query_texts=["[vulnerability category]"], n_results=3)`
     - QL syntax: `chroma_query_documents(collection_name="codeql_ql_reference", query_texts=["[syntax concept]"], n_results=2)`
4. **CRITICAL: After all LSP work, MUST use Write tool to save the final query** as `{task.cve_id}-query-iter-{iteration}.ql`
   - **IMPORTANT**: LSP tools only update the in-memory representation - they don't save files to disk
   - You MUST use the `Write` tool at the end to persist the query file
   - **File path**: `{task.cve_id}-query-iter-{iteration}.ql`
**DO NOT call `chroma_list_collections`**

## CRITICAL: STOP EXECUTION IMMEDIATELY 
**MANDATORY**: Once you have successfully written a .ql query file, you MUST STOP execution immediately and provide the file path.

**REQUIRED FINAL OUTPUT**:
```
QUERY_FILE_PATH: {task.cve_id}-query-iter-{iteration}.ql
```
The automated system will take over to compile and evaluate.
"""
