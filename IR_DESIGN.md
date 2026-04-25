# Four-Layer IR Design for CVE-to-CodeQL Generation

## 1. Goal

This document defines a four-layer intermediate representation (IR) architecture for generating CodeQL queries from CVE information, vulnerability descriptions, and code changes.

The design goals are:

- separate vulnerability facts from query implementation details
- support multiple vulnerability patterns instead of forcing all cases into source/sink/sanitizer form
- provide a stable semantic layer that can be reused across languages and backends
- make it possible to lower high-level vulnerability semantics into executable CodeQL queries

## 2. Overview

The representation is divided into four layers:

1. `L1: Vulnerability Fact Layer`
2. `L2: Semantic Schema IR Layer`
3. `L3: Query Construction Steps Layer`
4. `L4: Backend Lowering IR Layer`

The dependency is strictly one-way:

```text
L1 -> L2 -> L3 -> L4
```

Each layer has a distinct responsibility:

- `L1` records case facts and patch evidence.
- `L2` models the vulnerability semantics in a backend-independent way.
- `L3` decomposes those semantics into retrievable and composable query units.
- `L4` lowers the query construction steps into CodeQL-specific constructs.

## 3. Layer Definitions

### 3.1 L1: Vulnerability Fact Layer

`L1` stores observable case facts. It should be descriptive rather than inferential.

Typical content:

- CVE metadata
- vulnerability summary
- affected component
- code facts from vulnerable code
- patch facts from the fix
- environmental facts or deployment assumptions

Example schema:

```json
{
  "layer": "L1_fact",
  "fact_version": "1.0",
  "case_id": "CVE-2025-27818",
  "metadata": {
    "cve_id": "CVE-2025-27818",
    "language": "java",
    "project": "Apache Kafka",
    "cwe": ["CWE-184", "CWE-183"]
  },
  "code_facts": [],
  "patch_facts": [],
  "environment_facts": []
}
```

Constraints:

- `L1` must not contain CodeQL code.
- `L1` should avoid backend terms such as `DataFlow::Configuration`.
- `L1` should avoid overcommitting to source/sink/sanitizer unless the case is clearly a taint-flow vulnerability.

### 3.2 L2: Semantic Schema IR Layer

`L2` is the core semantic layer. It models vulnerability-relevant entities, relations, constraints, and guards.

Base structure:

```json
{
  "layer": "L2_schema_ir",
  "schema_version": "2.0",
  "case_id": "CVE-2025-27818",
  "pattern_type": "incomplete_security_policy",
  "entities": [],
  "relations": [],
  "constraints": [],
  "guards": [],
  "environment_conditions": [],
  "evidence": [],
  "reporting": {}
}
```

#### Core Object Types

Recommended entity kinds:

- `input`
- `subject`
- `policy`
- `policy_member`
- `check`
- `action`
- `config_key`
- `config_value`
- `constant`
- `api_call`
- `api_result`
- `container`
- `transform`
- `sanitizer`
- `guard_value`

Recommended relation types:

- `reads_from`
- `derived_from`
- `flows_to`
- `checks`
- `protects`
- `uses_policy`
- `contains_member`
- `missing_member`
- `compares_against`
- `controls`
- `blocks`
- `allows`
- `normalizes`
- `validates`
- `aliases`

#### Why L2 Must Be Typed by Pattern

Not all CVEs are taint-flow vulnerabilities. If every case is forced into `source/sink/sanitizer`, many security patterns are modeled poorly.

For that reason, `L2` is classified by `pattern_type`.

Recommended top-level pattern types:

- `taint_flow`
- `missing_validation`
- `incomplete_security_policy`
- `unsafe_default`
- `authorization_bypass`
- `state_or_lifecycle_violation`

### 3.3 L3: Query Construction Steps Layer

`L3` is not a full symbolic verification DAG. Instead, it defines a set of query construction steps, where each step corresponds to one complete semantic unit that can be independently retrieved, translated into a CodeQL fragment, and later composed into a full query.

The role of `L3` is therefore threefold:

- provide retrieval intent for vector search and official-query lookup
- provide natural-language guidance for fragment generation
- provide lightweight symbol interfaces for fragment composition

Base structure:

```json
{
  "layer": "L3_query_construction_steps",
  "plan_version": "1.0",
  "case_id": "CVE-2025-27818",
  "goal": "decompose L2 semantics into retrievable and composable query units",
  "steps": []
}
```

Each step should include:

```json
{
  "step_id": "step_id",
  "semantic_unit": "string",
  "goal": "string",
  "description": "string",
  "l2_refs": ["entity_or_relation_or_constraint_id"],
  "requires_symbols": ["symbol_name"],
  "produces_symbols": ["symbol_name"],
  "fragment_type": "predicate|where_clause|helper_class|select_clause|query_skeleton",
  "retrieval_hints": {
    "keywords": ["string"],
    "candidate_classes": ["string"],
    "candidate_predicates": ["string"],
    "reference_query_patterns": ["string"]
  },
  "expected_output": "string"
}
```

Recommended design rules for a step:

- one step should correspond to one complete semantic unit rather than one raw field
- one step should usually map to one helper predicate, one relation predicate, one constraint fragment, or one reporting fragment
- `description` should be natural-language friendly for LLMs
- `retrieval_hints` should guide vector retrieval and official-query retrieval
- `requires_symbols` and `produces_symbols` should expose a lightweight fragment interface

Constraints:

- `L3` should not embed full backend code.
- `L3` should remain backend-independent.
- `L3` should be fragment-oriented rather than execution-plan oriented.

### 3.4 L4: Backend Lowering IR Layer

`L4` is backend-specific. For this project, the main target backend is CodeQL.

Base structure:

```json
{
  "layer": "L4_backend_lowering",
  "backend": "codeql",
  "backend_version": "1.0",
  "language": "java",
  "query_kind": "problem|path-problem",
  "imports": [],
  "ir_to_predicate_map": [],
  "predicate_templates": [],
  "select_template": {}
}
```

This layer may contain:

- query kind selection
- library imports
- mapping from IR relations/constraints to predicates
- predicate generation templates
- alert anchor rules
- final select message templates

Constraints:

- `L4` must not redefine the vulnerability semantics already captured in `L2`.
- `L4` should only decide how to implement and report the semantics.

## 4. Schema IR Subtypes

This section defines the minimal slots required for each major `pattern_type`.

### 4.1 `taint_flow`

Use for injection, traversal, deserialization, or other classic source-to-sink vulnerabilities.

Required slots:

```json
{
  "pattern_type": "taint_flow",
  "required_slots": {
    "sources": ["entity_id"],
    "sinks": ["entity_id"],
    "propagators": ["entity_id"],
    "sanitizers": ["entity_id"],
    "flow_constraints": ["constraint_id"]
  }
}
```

### 4.2 `missing_validation`

Use when an operation should be guarded by validation but is not.

Required slots:

```json
{
  "pattern_type": "missing_validation",
  "required_slots": {
    "subject": "entity_id",
    "dangerous_action": "entity_id",
    "expected_validation": "entity_id",
    "missing_guard": "guard_id"
  }
}
```

### 4.3 `incomplete_security_policy`

Use when a policy exists, but a required rule or blocked member is absent.

Required slots:

```json
{
  "pattern_type": "incomplete_security_policy",
  "required_slots": {
    "policy": "entity_id",
    "policy_kind": "denylist|allowlist|capability_set|regex_policy",
    "subject": "entity_id",
    "policy_check": "entity_id",
    "required_member_or_rule": "entity_id",
    "violation_constraint": "constraint_id"
  }
}
```

### 4.4 `unsafe_default`

Use when a default value enables unsafe behavior.

Required slots:

```json
{
  "pattern_type": "unsafe_default",
  "required_slots": {
    "default_value": "entity_id",
    "controlled_feature": "entity_id",
    "safe_expected_value": "entity_id",
    "unsafe_condition": "constraint_id"
  }
}
```

### 4.5 `authorization_bypass`

Use when authorization is missing, mis-scoped, or bound to the wrong object.

Required slots:

```json
{
  "pattern_type": "authorization_bypass",
  "required_slots": {
    "principal": "entity_id",
    "protected_resource": "entity_id",
    "authorization_check": "entity_id",
    "missing_or_incorrect_binding": "constraint_id"
  }
}
```

### 4.6 `state_or_lifecycle_violation`

Use for use-after-free, double free, invalid transitions, or lifecycle misuse.

Required slots:

```json
{
  "pattern_type": "state_or_lifecycle_violation",
  "required_slots": {
    "resource": "entity_id",
    "state_transition": "entity_id",
    "unsafe_action": "entity_id",
    "state_constraint": "constraint_id"
  }
}
```

## 5. Optional Taint View

To avoid forcing every case into taint analysis, `source/sink/sanitizer` should be modeled as an optional view instead of a mandatory top-level schema.

Example:

```json
{
  "analysis_views": {
    "taint_view": {
      "sources": [],
      "sinks": [],
      "sanitizers": []
    }
  }
}
```

Rules:

- mandatory for `taint_flow`
- optional for non-taint patterns
- omitted when it distorts the vulnerability semantics

## 6. Example: `CVE-2025-27818`

This case is best modeled as `incomplete_security_policy`, not as a classic taint-flow vulnerability.

Example `L2` fragment:

```json
{
  "layer": "L2_schema_ir",
  "schema_version": "2.0",
  "pattern_type": "incomplete_security_policy",
  "entities": [
    {
      "id": "policy_default",
      "kind": "policy",
      "policy_kind": "denylist",
      "value_shape": "comma_separated_class_names"
    },
    {
      "id": "subject_login_module",
      "kind": "subject",
      "value_shape": "class_name"
    },
    {
      "id": "check_membership",
      "kind": "check",
      "check_kind": "membership_test"
    },
    {
      "id": "required_blocked_member",
      "kind": "policy_member",
      "value": "com.sun.security.auth.module.LdapLoginModule"
    }
  ],
  "relations": [
    {
      "id": "rel_check_uses_policy",
      "type": "uses_policy",
      "from": "check_membership",
      "to": "policy_default"
    },
    {
      "id": "rel_check_tests_subject",
      "type": "checks",
      "from": "check_membership",
      "to": "subject_login_module"
    }
  ],
  "constraints": [
    {
      "id": "constraint_missing_required_member",
      "kind": "missing_member",
      "target": "policy_default",
      "member": "required_blocked_member"
    }
  ],
  "guards": [
    {
      "id": "guard_policy_contains_required_member",
      "kind": "contains_member",
      "target": "policy_default",
      "member": "required_blocked_member"
    }
  ]
}
```

Example `L3` fragment:

```json
{
  "layer": "L3_query_construction_steps",
  "plan_version": "1.0",
  "goal": "detect incomplete denylist default used in login-module policy check",
  "steps": [
    {
      "step_id": "step_locate_policy_default",
      "semantic_unit": "policy_binding",
      "goal": "Locate the default denylist policy artifact",
      "description": "Bind the constant, field, or literal used as the default value of the disallowed login modules configuration.",
      "l2_refs": ["ent_policy_default", "ent_policy_key"],
      "requires_symbols": [],
      "produces_symbols": ["policyDefaultExpr"],
      "fragment_type": "predicate",
      "retrieval_hints": {
        "keywords": [
          "System.getProperty default value",
          "default denylist constant",
          "field initializer",
          "string literal argument"
        ],
        "candidate_classes": [
          "MethodAccess",
          "StringLiteral",
          "Field"
        ],
        "candidate_predicates": [
          "hasQualifiedName",
          "getArgument",
          "getValue"
        ],
        "reference_query_patterns": [
          "API argument matching",
          "constant binding"
        ]
      },
      "expected_output": "A helper predicate that binds the default denylist definition."
    },
    {
      "step_id": "step_locate_policy_check",
      "semantic_unit": "check_binding",
      "goal": "Locate the denylist membership check",
      "description": "Find the membership test that checks whether the login module name is contained in the disallowed login module set.",
      "l2_refs": ["ent_policy_check", "ent_subject_login_module"],
      "requires_symbols": [],
      "produces_symbols": ["policyCheckCall", "loginModuleExpr"],
      "fragment_type": "predicate",
      "retrieval_hints": {
        "keywords": [
          "Set.contains membership check",
          "login module name check",
          "security policy check"
        ],
        "candidate_classes": [
          "MethodAccess",
          "Expr"
        ],
        "candidate_predicates": [
          "hasQualifiedName",
          "getArgument"
        ],
        "reference_query_patterns": [
          "method call matching",
          "membership test matching"
        ]
      },
      "expected_output": "A helper predicate that binds the policy check call and the checked login module expression."
    },
    {
      "step_id": "step_relate_check_to_policy",
      "semantic_unit": "policy_check_relation",
      "goal": "Relate the policy check to the default denylist artifact",
      "description": "Generate a fragment that constrains the denylist set used in the membership check to be derived from the default policy value.",
      "l2_refs": ["rel_check_uses_policy"],
      "requires_symbols": ["policyDefaultExpr", "policyCheckCall"],
      "produces_symbols": ["validatedPolicyCheck"],
      "fragment_type": "predicate",
      "retrieval_hints": {
        "keywords": [
          "local data flow from default value to contains qualifier",
          "collection built from split trim collect toSet",
          "derived from policy default"
        ],
        "candidate_classes": [
          "DataFlow",
          "MethodAccess",
          "Expr"
        ],
        "candidate_predicates": [
          "localFlow",
          "getQualifier",
          "getArgument"
        ],
        "reference_query_patterns": [
          "local data flow",
          "collection derivation"
        ]
      },
      "expected_output": "A helper predicate that proves the check uses the default policy value."
    },
    {
      "step_id": "step_constrain_missing_member",
      "semantic_unit": "policy_completeness_constraint",
      "goal": "Constrain the default policy to be incomplete",
      "description": "Generate a constraint fragment requiring that the default denylist does not contain the required blocked member LdapLoginModule.",
      "l2_refs": ["con_missing_required_member", "guard_policy_contains_required_member"],
      "requires_symbols": ["policyDefaultExpr"],
      "produces_symbols": ["incompletePolicyDefault"],
      "fragment_type": "where_clause",
      "retrieval_hints": {
        "keywords": [
          "string containment check",
          "missing denylist member",
          "default policy completeness"
        ],
        "candidate_classes": [
          "StringLiteral",
          "Expr"
        ],
        "candidate_predicates": [
          "getValue",
          "matches",
          "regexpMatch"
        ],
        "reference_query_patterns": [
          "string value filtering",
          "negative membership constraint"
        ]
      },
      "expected_output": "A where-clause fragment that constrains the policy default to omit the required blocked member."
    },
    {
      "step_id": "step_report_violation",
      "semantic_unit": "alert_reporting",
      "goal": "Report the incomplete security policy",
      "description": "Generate the final query skeleton and select clause that reports the incomplete default denylist at the policy definition site.",
      "l2_refs": ["report_policy_default"],
      "requires_symbols": ["policyDefaultExpr", "validatedPolicyCheck", "incompletePolicyDefault"],
      "produces_symbols": ["finalQuery"],
      "fragment_type": "select_clause",
      "retrieval_hints": {
        "keywords": [
          "CodeQL alert message",
          "problem query select clause",
          "report location anchor"
        ],
        "candidate_classes": [
          "Expr"
        ],
        "candidate_predicates": [],
        "reference_query_patterns": [
          "problem query reporting",
          "select anchor on literal or field"
        ]
      },
      "expected_output": "A final from/where/select skeleton that reports the violation using the policy default as the alert anchor."
    }
  ]
}
```

## 7. Design Rules

The following rules should hold across the whole system:

1. Facts, semantics, query-construction steps, and backend code generation must be separated.
2. `pattern_type` determines the required shape of `L2`.
3. `L3` must remain backend-independent.
4. `L4` must not reinterpret the vulnerability.
5. Taint concepts should be optional unless the case is actually a taint-flow vulnerability.

## 8. Recommended File Layout

For each CVE, the representation can be stored as:

- `cve_facts.json`
- `schema_ir.json`
- `query_construction_steps.json`
- `backend_codeql.json`

This layout corresponds directly to the four layers and keeps responsibilities explicit.
