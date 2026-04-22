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
3. `L3: Logic Plan IR Layer`
4. `L4: Backend Lowering IR Layer`

The dependency is strictly one-way:

```text
L1 -> L2 -> L3 -> L4
```

Each layer has a distinct responsibility:

- `L1` records case facts and patch evidence.
- `L2` models the vulnerability semantics in a backend-independent way.
- `L3` defines how those semantics should be validated in code.
- `L4` lowers the logic plan into CodeQL-specific constructs.

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

### 3.3 L3: Logic Plan IR Layer

`L3` defines the verification plan as a DAG of logical steps. It should describe how to validate the semantics in `L2`, but it should not contain full CodeQL code.

Base structure:

```json
{
  "layer": "L3_logic_plan",
  "plan_version": "1.0",
  "case_id": "CVE-2025-27818",
  "goal": "prove violation of L2 constraints",
  "steps": []
}
```

Each step should include:

```json
{
  "id": "step_id",
  "kind": "locate|bind|derive|relate|constrain|exclude|report",
  "intent": "string",
  "inputs": ["symbol_or_entity_id"],
  "outputs": ["symbol_or_entity_id"],
  "depends_on": ["step_id"],
  "operation": {
    "type": "symbolic_operation_type",
    "selector": {},
    "filters": [],
    "join_conditions": []
  },
  "success_criterion": "string",
  "failure_mode": "string"
}
```

Recommended step kinds:

- `locate`
- `bind`
- `derive`
- `relate`
- `constrain`
- `exclude`
- `report`

Constraints:

- `L3` should not embed full backend code.
- `L3` should make dependencies explicit.
- `L3` should be machine-plannable and machine-reorderable.

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
  "layer": "L3_logic_plan",
  "plan_version": "1.0",
  "goal": "detect incomplete denylist default used in login-module policy check",
  "steps": [
    {
      "id": "locate_policy_default",
      "kind": "locate",
      "inputs": [],
      "outputs": ["policy_default_binding"],
      "depends_on": [],
      "operation": {
        "type": "locate_policy_artifact"
      }
    },
    {
      "id": "locate_policy_check",
      "kind": "locate",
      "inputs": [],
      "outputs": ["policy_check_binding"],
      "depends_on": [],
      "operation": {
        "type": "locate_check"
      }
    },
    {
      "id": "relate_check_to_policy",
      "kind": "relate",
      "inputs": ["policy_default_binding", "policy_check_binding"],
      "outputs": ["validated_policy_check_pair"],
      "depends_on": ["locate_policy_default", "locate_policy_check"],
      "operation": {
        "type": "prove_policy_used_by_check"
      }
    },
    {
      "id": "constrain_missing_member",
      "kind": "constrain",
      "inputs": ["validated_policy_check_pair"],
      "outputs": ["violating_policy_check_pair"],
      "depends_on": ["relate_check_to_policy"],
      "operation": {
        "type": "prove_required_member_absent"
      }
    },
    {
      "id": "report_violation",
      "kind": "report",
      "inputs": ["violating_policy_check_pair"],
      "outputs": ["alert"],
      "depends_on": ["constrain_missing_member"],
      "operation": {
        "type": "emit_alert"
      }
    }
  ]
}
```

## 7. Design Rules

The following rules should hold across the whole system:

1. Facts, semantics, logic, and backend code generation must be separated.
2. `pattern_type` determines the required shape of `L2`.
3. `L3` must remain backend-independent.
4. `L4` must not reinterpret the vulnerability.
5. Taint concepts should be optional unless the case is actually a taint-flow vulnerability.

## 8. Recommended File Layout

For each CVE, the representation can be stored as:

- `cve_facts.json`
- `schema_ir.json`
- `logic_plan.json`
- `backend_codeql.json`

This layout corresponds directly to the four layers and keeps responsibilities explicit.
