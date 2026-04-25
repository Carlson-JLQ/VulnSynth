# A Formal Four-Layer Intermediate Representation for CVE-to-CodeQL Synthesis

## Abstract

We define a four-layer intermediate representation (IR) for synthesizing CodeQL queries from CVE descriptions, patch evidence, and code-level artifacts. The core motivation is that many vulnerability classes cannot be faithfully represented by a single source-sink-sanitizer abstraction. We therefore separate case facts, semantic structure, query-construction steps, and backend lowering into distinct layers. We further introduce a typed Schema IR with vulnerability-specific subtypes, enabling more precise modeling of taint-flow vulnerabilities, missing validation flaws, incomplete security policies, unsafe defaults, authorization bypasses, and state or lifecycle violations.

## 1. Introduction

Automated vulnerability-to-query generation requires an intermediate representation that is simultaneously:

- expressive enough to capture diverse vulnerability classes
- structured enough to support programmatic lowering into static analysis queries
- modular enough to avoid mixing case evidence, semantic abstractions, and backend-specific implementation details

Existing source-sink-sanitizer abstractions work well for taint-style vulnerabilities, but are insufficient for classes such as incomplete policy enforcement, unsafe defaults, or authorization binding failures. To address this limitation, we define a layered IR architecture and a typed semantic schema.

## 2. Four-Layer Architecture

Let the overall representation for a case be:

```text
IR = (L1, L2, L3, L4)
```

where:

- `L1` is the Vulnerability Fact Layer
- `L2` is the Semantic Schema IR Layer
- `L3` is the Query Construction Steps Layer
- `L4` is the Backend Lowering IR Layer

We impose a strict dependency order:

```text
L1 -> L2 -> L3 -> L4
```

That is, each layer may depend only on information from preceding layers.

### 2.1 Layer Semantics

Let:

- `F` denote observable facts
- `S` denote semantic objects and relations
- `P` denote query-construction step sets
- `B` denote backend lowering specifications

Then:

- `L1 = F`
- `L2 = phi(F) = S`
- `L3 = psi(S) = P`
- `L4 = omega(P) = B`

where `phi`, `psi`, and `omega` are transformation functions.

## 3. Vulnerability Fact Layer

We define the fact layer as:

```text
L1 = (M, C, D, E)
```

where:

- `M` is metadata
- `C` is a set of code facts
- `D` is a set of patch facts
- `E` is a set of environmental facts

A fact is a tuple:

```text
f = (id, kind, subject, proposition, evidence)
```

Properties:

1. `L1` is descriptive rather than inferential.
2. `L1` contains no backend-specific implementation constructs.
3. `L1` does not assume a fixed vulnerability pattern.

## 4. Semantic Schema IR

We define the semantic layer as:

```text
L2 = (T, Ent, Rel, Con, G, Env, Ev, Rep)
```

where:

- `T` is the vulnerability pattern type
- `Ent` is a finite set of entities
- `Rel` is a finite set of relations
- `Con` is a finite set of vulnerability constraints
- `G` is a finite set of guards
- `Env` is a finite set of environment conditions
- `Ev` is a finite set of evidence links
- `Rep` is a reporting specification

### 4.1 Entities

An entity is a tuple:

```text
e = (id, kind, attrs)
```

where `kind` ranges over a controlled vocabulary such as:

```text
input, subject, policy, policy_member, check, action,
config_key, config_value, constant, api_call, api_result,
container, transform, sanitizer, guard_value
```

### 4.2 Relations

A relation is a tuple:

```text
r = (id, type, src, dst, attrs)
```

where `src` and `dst` reference entity identifiers.

Typical relation types include:

```text
reads_from, derived_from, flows_to, checks, protects, uses_policy,
contains_member, missing_member, compares_against, controls,
blocks, allows, normalizes, validates, aliases
```

### 4.3 Constraints and Guards

A constraint expresses a condition whose satisfaction contributes to the vulnerable state.

```text
c = (id, kind, target, params)
```

A guard expresses a condition that should hold in the non-vulnerable state.

```text
g = (id, kind, target, params)
```

Informally:

- constraints characterize vulnerability
- guards characterize expected protection

## 5. Typed Schema IR

The semantic layer is parameterized by a pattern type `T`.

```text
T in {
  taint_flow,
  missing_validation,
  incomplete_security_policy,
  unsafe_default,
  authorization_bypass,
  state_or_lifecycle_violation
}
```

Each `T` induces a schema subtype with required semantic slots.

### 5.1 Taint Flow

For `T = taint_flow`, the minimal schema is:

```text
L2_taint = (Sources, Sinks, Propagators, Sanitizers, FlowConstraints)
```

Correctness condition:

```text
exists s in Sources, k in Sinks :
  reachable(s, k) and not blocked_by_sanitizer(s, k)
```

### 5.2 Missing Validation

For `T = missing_validation`, the minimal schema is:

```text
L2_mv = (Subject, DangerousAction, ExpectedValidation, MissingGuard)
```

Correctness condition:

```text
uses(DangerousAction, Subject) and not validated_by(Subject, ExpectedValidation)
```

### 5.3 Incomplete Security Policy

For `T = incomplete_security_policy`, the minimal schema is:

```text
L2_isp = (Policy, PolicyKind, Subject, PolicyCheck, RequiredMemberOrRule, ViolationConstraint)
```

Correctness condition:

```text
uses_policy(PolicyCheck, Policy) and
checks(PolicyCheck, Subject) and
missing(Policy, RequiredMemberOrRule)
```

This pattern is especially useful for cases in which a security check exists syntactically, but the policy it enforces is semantically incomplete.

### 5.4 Unsafe Default

For `T = unsafe_default`, the minimal schema is:

```text
L2_ud = (DefaultValue, ControlledFeature, SafeExpectedValue, UnsafeCondition)
```

### 5.5 Authorization Bypass

For `T = authorization_bypass`, the minimal schema is:

```text
L2_ab = (Principal, ProtectedResource, AuthorizationCheck, IncorrectBinding)
```

### 5.6 State or Lifecycle Violation

For `T = state_or_lifecycle_violation`, the minimal schema is:

```text
L2_slv = (Resource, StateTransition, UnsafeAction, StateConstraint)
```

## 6. Query Construction Steps Layer

We define the query-construction layer as:

```text
L3 = (Goal, Steps)
```

where:

- `Goal` is the construction objective
- `Steps` is a finite set of semantic-unit steps

Each step is a tuple:

```text
step = (id, u, d, R, In, Out, t, H, Exp)
```

where:

- `u` is the semantic unit type
- `d` is a natural-language description
- `R` is a set of references into `L2`
- `In` is the required symbol set
- `Out` is the produced symbol set
- `t` is the fragment type
- `H` is the retrieval-hint bundle
- `Exp` is the expected output contract

Unlike a symbolic execution plan, `L3` is not required to form a DAG. Its purpose is not to encode a fully executable proof strategy, but to decompose `L2` into retrievable and composable semantic units. A step is considered well-formed if it can be translated into one of a small number of code-fragment classes, such as:

```text
helper_predicate, relation_predicate, constraint_fragment,
where_clause, select_clause, query_skeleton
```

This yields three important properties:

1. each step can be used as a retrieval query for CodeQL knowledge
2. each step can be translated into an independent query fragment
3. the overall layer remains backend-independent at the semantic level

## 7. Backend Lowering IR

We define the backend lowering layer as:

```text
L4 = (Backend, QueryKind, Imports, Map, PredTmpl, SelectTmpl)
```

where:

- `Backend` identifies the target analysis backend
- `QueryKind` identifies the query family, such as `problem` or `path-problem`
- `Imports` is the required library set
- `Map` maps semantic relations and constraints into backend predicates
- `PredTmpl` is a set of predicate templates
- `SelectTmpl` defines reporting behavior

For CodeQL:

- semantic entities typically lower to binding predicates
- `flows_to` lowers to `DataFlow` or `TaintTracking`
- structural relations such as `uses_policy` lower to join predicates
- constraints such as `missing_member` lower to value or set predicates

## 8. Optional Taint View

We explicitly treat taint-oriented constructs as a view rather than a universal ontology.

Let:

```text
TV = (Sources, Sinks, Sanitizers)
```

Then:

- if `T = taint_flow`, `TV` is mandatory
- otherwise, `TV` is optional

This prevents semantic distortion in non-taint cases.

## 9. Example: CVE-2025-27818

We classify `CVE-2025-27818` as:

```text
T = incomplete_security_policy
```

because the vulnerability arises from an incomplete denylist, not from a classical taint flow.

Let:

- `P` be the default disallowed-login-module policy
- `S` be the login module name
- `C` be the membership check
- `R` be the required blocked module `LdapLoginModule`

Then the vulnerable condition is:

```text
uses_policy(C, P) and checks(C, S) and missing(P, R)
```

The corresponding query-construction steps can be expressed as:

1. locate the policy artifact `P`
2. locate the policy check `C`
3. construct a fragment linking `C` to `P`
4. construct a fragment enforcing `missing(P, R)`
5. construct a reporting fragment anchored at `P`

These steps are intended to drive retrieval and fragment generation rather than to encode a strict proof DAG. They do not require a path-problem encoding unless additional provenance evidence is desired.

## 10. Design Invariants

We require the following invariants:

1. `L1` contains facts, not backend logic.
2. `L2` contains semantics, not executable query code.
3. `L3` contains semantic-unit construction steps, not backend syntax.
4. `L4` contains lowering strategy, not new vulnerability semantics.
5. Every inferred semantic object in `L2` should be traceable to evidence from `L1`.

## 11. Conclusion

The proposed four-layer IR separates evidence, semantics, query construction, and backend realization. Its key novelty lies in the typed Schema IR and the semantic-unit-based `L3`, which avoid overfitting all vulnerabilities to taint-style abstractions or compiler-like proof plans. This improves fidelity for non-taint vulnerabilities such as incomplete policy enforcement, unsafe defaults, and authorization failures, while still supporting classical source-sink-sanitizer modeling where appropriate.
