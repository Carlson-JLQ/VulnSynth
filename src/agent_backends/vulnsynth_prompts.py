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
  - `chroma_query_documents` against collections such as `codeql_local_queries`, `codeql_ql_reference`, `codeql_language_guides`, and `cwe_data`

## CVE Description
{cve_desc_block}

## Fix Diff
```diff
{task.fix_commit_diff}
```
"""


def build_l1_prompt(task) -> str:
    guidance = load_ir_guidance()
    return f"""
# VulnSynth Plan Agent: Stage 1 (Generate L1 Fact Layer)

You are generating the `L1` result for VulnSynth.

Your task is to:
1. inspect the repository and fix diff
2. extract vulnerability facts from code and tests
3. summarize the vulnerability pattern at the factual level
4. output exactly one JSON object for the L1 fact layer

{_shared_context(task)}

## L1 Design Guidance
{guidance["l1_design"]}

## L1 Formal Guidance
{guidance["fact_formal"]}

## Requirements
- Focus on observable facts, not speculative CodeQL implementation details.
- Use evidence from vulnerable code, fix diff, and regression tests.
- Include `code_facts`, `patch_facts`, and `environment_facts`.
- Include a `pattern_summary` that names the likely vulnerability pattern and fix strategy.
- Do not generate L2 or L3 in this stage.

## Output Contract
- Return exactly one JSON object.
- Do not wrap the JSON in markdown fences.
- The top-level `layer` field must be `"L1_fact"`.
- Make sure the JSON is syntactically valid.
"""


def build_l2_prompt(task, l1_json: str) -> str:
    guidance = load_ir_guidance()
    return f"""
# VulnSynth Plan Agent: Stage 2 (Generate L2 Semantic Schema IR)

You are generating the `L2` result for VulnSynth.

Your task is to:
1. read the L1 factual result below
2. classify the case into the most suitable `pattern_type`
3. construct a typed semantic schema with entities, relations, constraints, guards, environment conditions, evidence, and reporting
4. output exactly one JSON object for the L2 schema IR

{_shared_context(task)}

## Input L1 JSON
{l1_json}

## L2 Design Guidance
{guidance["l2_design"]}

## L2 Formal Guidance
{guidance["schema_formal"]}

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
    guidance = load_ir_guidance()
    return f"""
# VulnSynth Plan Agent: Stage 3 (Generate L3 Query Construction Steps)

You are generating the `L3` result for VulnSynth.

Your task is to:
1. read the L1 and L2 results below
2. decompose the L2 semantics into retrievable and composable query-construction steps
3. make each step a complete semantic unit that can be translated into a CodeQL fragment
4. output exactly one JSON object for the L3 query-construction steps layer

{_shared_context(task)}

## Input L1 JSON
{l1_json}

## Input L2 JSON
{l2_json}

## L3 Design Guidance
{guidance["l3_design"]}

## L3 Formal Guidance
{guidance["l3_formal"]}

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
