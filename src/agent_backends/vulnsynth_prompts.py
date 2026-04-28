"""Prompt builders for the VulnSynth plan agent."""

from __future__ import annotations

import os
from functools import lru_cache


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _extract_between(text: str, start_marker: str, end_marker: str | None) -> str:
    start = text.find(start_marker)
    if start == -1:
        return ""
    start += len(start_marker)
    end = len(text) if end_marker is None else text.find(end_marker, start)
    if end == -1:
        end = len(text)
    return text[start:end].strip()


@lru_cache(maxsize=1)
def load_ir_guidance() -> dict:
    """Load compact guidance excerpts from the IR design/formalization docs."""
    design = _read_file(os.path.join(_repo_root(), "IR_DESIGN.md"))
    formal = _read_file(os.path.join(_repo_root(), "IR_FORMALIZATION_PAPER_STYLE.md"))

    return {
        "l1_design": _extract_between(
            design,
            "### 3.1 L1: Vulnerability Fact Layer",
            "### 3.2 L2: Semantic Schema IR Layer",
        ),
        "l2_design": _extract_between(
            design,
            "### 3.2 L2: Semantic Schema IR Layer",
            "### 3.3 L3: Query Construction Steps Layer",
        ),
        "l3_design": _extract_between(
            design,
            "### 3.3 L3: Query Construction Steps Layer",
            "### 3.4 L4: Backend Lowering IR Layer",
        ),
        "fact_formal": _extract_between(
            formal,
            "## 3. Vulnerability Fact Layer",
            "## 4. Semantic Schema IR",
        ),
        "schema_formal": _extract_between(
            formal,
            "## 4. Semantic Schema IR",
            "## 5. Typed Schema IR",
        ),
        "l3_formal": _extract_between(
            formal,
            "## 6. Query Construction Steps Layer",
            "## 7. Backend Lowering IR",
        ),
    }


def _shared_context(task) -> str:
    repo_path = task.repo_path
    diff_path = task.diff_path
    cve_desc = (task.cve_description or "").strip()
    cve_desc_block = cve_desc if cve_desc else "No pre-fetched CVE description was available."
    return f"""
## Case Context
- CVE ID: `{task.cve_id}`
- CVE directory: `{task.cve_dir}`
- Repository root: `{repo_path}`
- Fix diff file: `{diff_path}`

## Working Materials
- You may inspect the repository under `{repo_path}`.
- You may inspect the diff file at `{diff_path}`.
- You may use Chroma tools when helpful, especially:
  - `chroma_get_documents` against `{task.nvd_cache}` for NVD context
  - `chroma_query_documents` against `codeql_ql_reference`, `cwe_data`, and language-specific CodeQL collections (for example `java_codeql_stdlib`, `java_codeql_language_guides`, `java_codeql_local_queries`)

## CVE Description
{cve_desc_block}
"""


def build_l1_prompt(task) -> str:
    return f"""
# VulnSynth Plan Agent: Stage 1 (Generate L1 Fact Layer)

You are generating the `L1` result for VulnSynth.

Your task is to:
1. inspect the repository and fix diff
2. extract vulnerability facts from code and tests
3. summarize the vulnerability pattern at the factual level
4. output exactly one JSON object for the L1 fact layer

Tooling rules:
- You MAY use tools to read files and inspect the repository.
- Do NOT call `TodoWrite`.
- Do NOT output a plan.
- Your final answer MUST be the single JSON object required by the Output Contract.

{_shared_context(task)}

## Requirements
- Focus on observable facts, not speculative CodeQL implementation details.
- Use evidence from vulnerable code, fix diff, and regression tests.
- Include `code_facts`, `patch_facts`, and `environment_facts`.
- Include a `pattern_summary` that names the likely vulnerability pattern and fix strategy.
- Keep outputs compact: prefer <= 20 `code_facts` and <= 10 `patch_facts` unless strictly necessary.
- Do not generate L2 or L3 in this stage.

## Output Contract
- Return exactly one JSON object.
- Do not wrap the JSON in markdown fences.
- The top-level `layer` field must be `"L1_fact"`.
- Make sure the JSON is syntactically valid.
"""


def build_l2_prompt(task, l1_json: str) -> str:
    return f"""
# VulnSynth Plan Agent: Stage 2 (Generate L2 Semantic Schema IR)

You are generating the `L2` result for VulnSynth.

Your task is to:
1. read the L1 factual result below
2. classify the case into the most suitable `pattern_type`
3. construct a typed semantic schema with entities, relations, constraints, guards, environment conditions, evidence, and reporting
4. output exactly one JSON object for the L2 schema IR

Tooling rules:
- Do NOT call `TodoWrite`.
- Do NOT output a plan.
- Your final answer MUST be the single JSON object required by the Output Contract.

{_shared_context(task)}

## Input L1 JSON
{l1_json}

## Requirements
- Choose the most appropriate `pattern_type`; do not force taint-flow unless the case truly is taint-flow.
- Use stable `id` fields and refer back to L1 evidence with `evidence_refs`.
- Model the vulnerability in backend-independent semantic terms.
- Do not include CodeQL code or full query snippets.
- Do not generate L3 in this stage.

## Output Contract
- Return exactly one JSON object.
- Do not wrap the JSON in markdown fences.
- The top-level `layer` field must be `"L2_schema_ir"`.
- Make sure the JSON is syntactically valid.
"""


def build_l3_prompt(task, l1_json: str, l2_json: str) -> str:
    return f"""
# VulnSynth Plan Agent: Stage 3 (Generate L3 Query Construction Steps)

You are generating the `L3` result for VulnSynth.

Your task is to:
1. read the L1 and L2 results below
2. decompose the L2 semantics into retrievable and composable query-construction steps
3. make each step a complete semantic unit that can be translated into a CodeQL fragment
4. output exactly one JSON object for the L3 query-construction steps layer

Tooling rules:
- Do NOT call `TodoWrite`.
- Do NOT output a plan.
- Your final answer MUST be the single JSON object required by the Output Contract.

{_shared_context(task)}

## Input L1 JSON
{l1_json}

## Input L2 JSON
{l2_json}

## Requirements
- Each step must correspond to one complete semantic unit, not a raw field.
- Use natural-language descriptions suitable for retrieval and LLM fragment generation.
- Include `l2_refs`, `requires_symbols`, `produces_symbols`, `fragment_type`, `retrieval_hints`, and `expected_output`.
- Keep the steps backend-independent, but make them clearly translatable into CodeQL fragments.
- Do not generate full CodeQL code in this stage.

## Output Contract
- Return exactly one JSON object.
- Do not wrap the JSON in markdown fences.
- The top-level `layer` field must be `"L3_query_construction_steps"`.
- Make sure the JSON is syntactically valid.
"""


def build_fragment_prompt(
    task,
    l1_json: str,
    l2_json: str,
    l3_json: str,
    step_json: str,
    retrieval_plan_json: str,
    language: str,
    *,
    loop_feedback_json: str = "",
) -> str:
    feedback_block = (
        f"\n## Feedback Loop Guidance\n{loop_feedback_json}\n" if (loop_feedback_json or "").strip() else ""
    )

    lang_api_note = ""
    if str(language).strip().lower() == "java":
        lang_api_note = (
            "\n## Language API Notes (Java)\n"
            "- In this environment, Java method invocations use `MethodCall` (NOT `MethodAccess`).\n"
            "- If you need to model a call site like `x.getResource(y)`, use `MethodCall` and its APIs (for example `getMethod()`, `getArgument(i)`, `hasQualifier()` / `getQualifier()`).\n"
        )
    return f"""
# VulnSynth Gen Agent: Step Fragment Generation

You are generating one CodeQL fragment for one L3 query-construction step.

Your task is to:
1. read the L1/L2/L3 context below
2. focus only on the provided step
3. use MCP tools when helpful, including Chroma collections that match the retrieval plan
4. generate one composable CodeQL fragment for this step
5. return exactly one JSON object

{_shared_context(task)}

## Target Language
- CodeQL language: `{language}`

## Input L1 JSON
{l1_json}

## Input L2 JSON
{l2_json}

## Input L3 JSON
{l3_json}

## Current Step JSON
{step_json}

## Retrieval Plan
{retrieval_plan_json}

{feedback_block}

## Retrieval Guidance
- Use `nist_cve_cache` for CVE-specific grounding when needed.
- Use `codeql_ql_reference` for shared CodeQL syntax, classes, and predicate conventions.
- Use `cwe_data` for weakness semantics when useful.
- Use the language-specific collections listed in the retrieval plan for classes, predicates, guides, and local query patterns.
- Prefer language-specific collections for concrete CodeQL APIs and example query structure.
- Use the step `description`, `retrieval_hints`, and retrieval plan query views as your retrieval inputs.
- IMPORTANT: Only query Chroma collections listed in the Retrieval Plan (see `allowed_collection_names` / keys of `collection_query_map`). Do not invent or guess collection names.
- If the Retrieval Plan includes `collection_where_filters`, pass the corresponding `where` filter when calling `chroma_query_documents`.

## Fragment Requirements
- Generate a fragment only for the current step, not the whole query.
- Respect `requires_symbols` and `produces_symbols`.
- Match the requested `fragment_type`.
- Keep the fragment composable with later steps.
- Prefer helper predicates for reusable logic.
- The fragment may define helper predicates, helper classes, or where/select snippets depending on the step.
- Do not invent APIs that do not exist in `{language}` CodeQL libraries.

{lang_api_note}

## Output Contract
- Return exactly one JSON object.
- Do not wrap the JSON in markdown fences.
- The JSON must contain:
  - `step_id`
  - `fragment_type`
  - `summary`
  - `required_imports`
  - `defines_symbols`
  - `depends_on_symbols`
  - `codeql_fragment`
  - `notes`
- `codeql_fragment` must be a plain string containing only CodeQL code for this step.
- Make sure the JSON is syntactically valid.
"""


def build_diagnosis_prompt(
    task,
    *,
    iteration: int,
    validation_summary_path: str,
    failure_report_path: str,
    patch_policy_path: str,
    validation_summary_snippet: str = "",
    failure_report_snippet: str = "",
) -> str:
    """Build prompt for Diagnoser Agent.

    The Diagnoser Agent must output strictly one JSON object with proposed patches.
    Patches are constrained by `patch_policy_yaml` and must use JSON Pointer paths.
    """

    return f"""
# VulnSynth Diagnoser Agent: Policy-Constrained Repair

You are a Diagnoser Agent. Your job is to translate validation signals into a
structured diagnosis and a small set of minimal patches that are allowed by the
patch policy.

Key rules:
- You MUST output EXACTLY ONE JSON object and NOTHING ELSE.
- Do NOT wrap JSON in markdown fences.
- You may propose patches only using:
  - op: append | replace | merge | remove
  - file: L1_fact.json | L2_schema_ir.json | L3_logic_plan.json | fragment_bundle.json | final_query.json
  - path: JSON Pointer (e.g. /guards/0, /steps/2/retrieval_hints)
- Every patch MUST include a non-empty `reason`.
- Prefer small, targeted patches (<= 5) over large rewrites.
- If uncertainty is high, set `primary_failure_type` to `unknown_failure` and return empty `proposed_patches`.

Repair strategy guidelines (important):
- Prefer controlling regeneration rather than rewriting the entire query.
- If the failure is localized to one or a few L3 steps (for example a wrong CodeQL API/type used in one helper predicate), prefer patching `fragment_bundle.json` to:
  - set `/regen_steps` to a list of step ids to rerun (e.g. `["step:identify_insecure_minimal_fallback_matcher"]`), or `["*"]` to rerun all fragments.
  - set `/feedback` (and optionally append to `/feedback_history`) with concise, actionable guidance that the next fragment generation pass must follow.
- Use `final_query.json` patches only when the fix is truly composition-only (cannot be attributed to a single step) or when you need to apply a minimal direct edit.
- When you patch `final_query.json:/query_code`, assume the system will *materialize the `.ql` file from that patched JSON*; do not rely on a subsequent composer rerun to preserve your change.

{_shared_context(task)}

## Iteration
- iteration: {int(iteration)}

## Artifacts (read from disk)
- Validation summary JSON: `{validation_summary_path}`
- Failure report JSON: `{failure_report_path}`
- Patch policy YAML (authoritative): `{patch_policy_path}`

Read these files first. They contain compilation/run signals and the full patch-policy constraints.

## Compact Snippets (optional; prefer disk)
Validation summary snippet:
{validation_summary_snippet}

Failure report snippet:
{failure_report_snippet}

## Output Contract (strict)
Return one JSON object with fields:
- case_id: string
- iteration: number
- primary_failure_type: string
- confidence: number (0..1)
- evidence: object (include key snippets like compile_success/vuln_hits/fixed_hits/compile_stderr_snippet)
- suspected_layers: array of strings (e.g. ["L2","L3","fragment","composer"])
- proposed_patches: array of patch objects (may be empty)

Each patch object:
- patch_id: string (optional)
- file: string (one of the allowed files)
- op: string (append|replace|merge|remove)
- path: string (JSON Pointer)
- value: any (required for append/replace/merge)
- precondition: object (optional)
- reason: string
"""


def build_query_composition_prompt(
    task,
    l1_json: str,
    l2_json: str,
    l3_json: str,
    fragment_bundle_json: str,
    language: str,
    *,
    loop_feedback_json: str = "",
) -> str:
    feedback_block = (
        f"\n## Feedback Loop Guidance\n{loop_feedback_json}\n" if (loop_feedback_json or "").strip() else ""
    )

    lang_api_note = ""
    if str(language).strip().lower() == "java":
        lang_api_note = (
            "\n## Language API Notes (Java)\n"
            "- Do NOT use `MethodAccess` (it is not available in this environment). Use `MethodCall` for Java method invocations.\n"
        )
    return f"""
# VulnSynth Gen Agent: Final Query Composition

You are composing a complete CodeQL query from previously generated step fragments.

Your task is to:
1. read the L1/L2/L3 context below
2. read all generated step fragments
3. combine them into one coherent, compilable CodeQL query
4. use MCP tools when helpful to verify language-specific classes, predicates, and query structure
5. return exactly one JSON object

{_shared_context(task)}

## Target Language
- CodeQL language: `{language}`

{lang_api_note}

## Input L1 JSON
{l1_json}

## Input L2 JSON
{l2_json}

## Input L3 JSON
{l3_json}

## Fragment Index (Read files from disk)
{fragment_bundle_json}

Use the `fragment_bundle_path` and each `qlfrag_path` in `fragment_refs` to read the generated step fragments.
Prefer composing from the `.qlfrag` files; use `fragment.json` only if you need metadata like `summary`.
Do NOT read `fragment_bundle_path` unless you truly need `regen_steps` for loop control.
`fragment_bundle.json` can be very large and is not needed for query composition when fragments are available.
Treat the injected feedback guidance below as authoritative for how to correct the query during this iteration.
{feedback_block}

## Composition Requirements
- Compose a single complete CodeQL query.
- Reconcile duplicate imports and overlapping helper predicates.
- Keep the final query aligned with the L2 vulnerability semantics.
- Use the L3 steps as the composition scaffold.
- Prefer a correct and coherent query over mechanically concatenating every fragment verbatim.
- Preserve the intended reporting anchor and final finding message.
- If some fragment should be folded into a `where` clause rather than kept as a separate predicate, do so.
- Do NOT emit predicate/function signatures without bodies (e.g., `predicate p(T x);`). Every predicate/function you define must have a body.
- Ensure helper predicate/class names are unique (do not redefine `getMethod`, `getEnclosingCallable`, etc.).
- Do not invent CodeQL APIs (including higher-order predicates). If unsure, use MCP retrieval to confirm.
- The final query must be suitable for writing to a `.ql` file.
- Do not return partial code.

## Output Contract
- Return exactly one JSON object.
- Do not wrap the JSON in markdown fences.
- The JSON must contain:
  - `case_id`
  - `language`
  - `query_kind`
  - `query_file_name`
  - `required_imports`
  - `supporting_predicates`
  - `query_code`
  - `composition_notes`
- `query_code` must be a complete CodeQL query as a plain string.
- Make sure the JSON is syntactically valid.
"""
