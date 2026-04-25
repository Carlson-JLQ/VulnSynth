下面给你一套可直接落地的 4 层表示定义。目标是让整个流程满足这几点：

- 上层表达漏洞语义，不绑死 CodeQL
- 中层可组合、可检索、可约束
- 下层可编译到不同 query 模板
- 不同 CVE 可按模式选择不同 Schema IR 子类型

**一、四层表示总览**

1. `L1: Vulnerability Fact Layer`
   记录 CVE 与补丁事实，尽量客观，不做过多推理。

2. `L2: Semantic Schema IR Layer`
   记录漏洞语义对象、关系、约束，是核心中间表示。
   这一层允许按漏洞模式分型。

3. `L3: Query Construction Steps Layer`
   记录“如何把 L2 中的语义拆成可独立实现的查询语义单元”。
   这一层面向检索、片段生成和最终组装，不直接写完整 CodeQL 代码。

4. `L4: Backend Lowering IR Layer`
   记录如何把查询构造步骤降级到 CodeQL。
   这一层才出现 CodeQL-specific 的库、predicate、query kind、模板选择。

---

**二、层间关系**

用一个统一的不变式约束：

- `L1` 只提供事实和证据
- `L2` 只提供语义建模
- `L3` 只提供查询构造步骤
- `L4` 只提供后端落地

形式化依赖：

```text
L1 -> L2 -> L3 -> L4
```

禁止反向污染：

- `L2` 不应出现 `DataFlow::Configuration`
- `L3` 不应直接出现完整 CodeQL 代码
- `L1` 不应硬编码 query 结构
- `L4` 不应改写漏洞语义

---

**三、统一元模型**

先定义所有层共享的基础概念。

```json
{
  "id": "string",
  "kind": "string",
  "name": "string",
  "description": "string",
  "tags": ["string"],
  "confidence": 0.0,
  "evidence_refs": ["string"]
}
```

统一引用规则：

- 所有实体必须有唯一 `id`
- 所有跨对象依赖都通过 `id` 引用
- 所有推理性对象都应能追溯到 `evidence_refs`

---

**四、L1: Vulnerability Fact Layer**

职责：描述“这个 CVE 里发生了什么”。

建议结构：

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
  "vulnerability_summary": {
    "title": "Incomplete default denylist for JAAS login modules",
    "impact": "Security bypass / SSRF-enabling misconfiguration path"
  },
  "code_facts": [
    {
      "id": "fact_default_constant",
      "kind": "code_fact",
      "subject": "DISALLOWED_LOGIN_MODULES_DEFAULT",
      "fact": "default denylist constant omits LdapLoginModule",
      "location": "clients/src/main/java/org/apache/kafka/common/security/JaasUtils.java"
    },
    {
      "id": "fact_policy_check",
      "kind": "code_fact",
      "subject": "throwIfLoginModuleIsNotAllowed",
      "fact": "runtime check uses Set.contains(loginModuleName)",
      "location": "clients/src/main/java/org/apache/kafka/common/security/JaasContext.java"
    }
  ],
  "patch_facts": [
    {
      "id": "fact_patch_add_member",
      "kind": "patch_fact",
      "fact": "patch adds LdapLoginModule to default denylist constant"
    }
  ],
  "environment_facts": [
    {
      "id": "fact_runtime_branch",
      "kind": "environment_fact",
      "fact": "default value is used only when overriding system property is absent"
    }
  ]
}
```

L1 的要求：

- 不引入 `source/sink/sanitizer` 这类抽象词，除非补丁事实明确支持
- 不写实现步骤
- 不写后端代码草图

---

**五、L2: Semantic Schema IR Layer**

这是核心层。建议采用：

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

L2 的基本对象分 6 类：

1. `entity`
   如 policy、subject、check、action、config_key、literal、api_result

2. `relation`
   表示实体间关系

3. `constraint`
   漏洞成立必须满足的约束

4. `guard`
   漏洞不存在时应满足的保护条件

5. `environment_condition`
   部署或运行条件，不一定静态可验证

6. `reporting`
   告警锚点和语义消息模板

---

**六、L2 的通用实体类型**

推荐先固定一组通用 `entity.kind`：

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

推荐通用 `relation.type`：

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

---

**七、Schema IR 分型**

这是最关键的部分。不要强迫所有 CVE 共用一个 schema。

建议至少定义这 6 个子类型：

1. `taint_flow`
2. `missing_validation`
3. `incomplete_security_policy`
4. `unsafe_default`
5. `authorization_bypass`
6. `state_or_lifecycle_violation`

---

**八、各子类型的最小字段**

**1. `taint_flow`**

适用于命令注入、路径遍历、SQL 注入、XSS 等。

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

最小语义：

- 存在不可信输入
- 输入经传播到危险使用点
- 中间没有有效净化

---

**2. `missing_validation`**

适用于“调用危险操作前缺少检查”。

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

最小语义：

- 某 subject 被用于 dangerous action
- 按设计应先经过 validation
- 实际缺失或条件不足

---

**3. `incomplete_security_policy`**

适用于你这个 CVE。

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

最小语义：

- 存在安全策略
- 存在策略执行点
- 某必须拦截成员或规则缺失
- 导致检查逻辑名义存在但实际保护不足

---

**4. `unsafe_default`**

适用于默认配置不安全、默认打开危险功能。

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

---

**5. `authorization_bypass`**

适用于权限判断缺失、作用域错配、对象绑定错误。

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

---

**6. `state_or_lifecycle_violation`**

适用于 UAF、双重释放、未初始化、竞态状态错序。

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

---

**九、`incomplete_security_policy` 的正式定义**

这是你当前最需要的。

语义定义：

```text
A case matches incomplete_security_policy iff:

1. There exists a policy P
2. There exists a subject S
3. There exists a check C such that C enforces P on S
4. There exists a required member or rule R that must be present in P
5. P is missing R under the vulnerable branch
6. Therefore C is semantically insufficient to block the dangerous case
```

对应 JSON 结构：

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

---

**十、L3: Query Construction Steps Layer**

L3 不再写完整 `codeql_sketch`，也不强制要求复杂的 DAG 依赖图。

更合适的做法是：把 L2 中的漏洞语义拆成若干个“完整语义单元 step”。每个 step 都描述一个可以独立检索、独立生成局部 CodeQL 片段、再参与最终组装的查询单元。

这一层的主要用途有三个：

1. 给向量数据库检索提供明确的语义目标
2. 给 LLM 生成局部 query 片段提供自然语言约束
3. 给最终 query 合成提供片段级接口信息

因此，L3 的重点不是严格执行顺序，而是：

- 这一步要实现什么语义单元
- 这一步适合检索哪些类、谓词、官方 query 模式
- 这一步期望输出什么类型的代码片段
- 这一步依赖和产出哪些语义符号

统一结构：

```json
{
  "layer": "L3_query_construction_steps",
  "plan_version": "1.0",
  "case_id": "CVE-2025-27818",
  "goal": "decompose L2 semantics into retrievable and composable query units",
  "steps": []
}
```

每个 step 建议采用轻量结构化字段：

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

这里有几个实现原则：

- 一个 step 对应一个“完整语义单元”，而不是单个字段
- 一个 step 最好最终对应一个辅助 predicate、一个约束片段，或一个 `select` 片段
- `description` 用自然语言写，便于 LLM 理解和检索
- `retrieval_hints` 用来驱动向量数据库和官方 query 检索
- `requires_symbols` 与 `produces_symbols` 用来约束片段拼接接口

对这个 CVE，L3 可定义为：

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

如果后续确实需要更强的编排能力，可以在不改变自然语言 step 主体的前提下，再额外补充一个轻量依赖字段；但在当前阶段，没有必要把 L3 设计成严格的验证 DAG。

---

**十一、L4: Backend Lowering IR Layer**

这层才是 CodeQL-specific。

统一结构：

```json
{
  "layer": "L4_backend_lowering",
  "backend": "codeql",
  "backend_version": "1.0",
  "language": "java",
  "query_kind": "problem|path-problem",
  "imports": [],
  "symbol_bindings": [],
  "predicate_templates": [],
  "select_template": {}
}
```

关键思想：L4 不是完整代码，而是“生成规格”。

建议字段：

- `query_kind`
- `imports`
- `ir_to_predicate_map`
- `predicate_templates`
- `alert_anchor_rule`
- `message_template`

例如：

```json
{
  "layer": "L4_backend_lowering",
  "backend": "codeql",
  "language": "java",
  "query_kind": "problem",
  "imports": ["java"],
  "ir_to_predicate_map": [
    {
      "ir_relation": "uses_policy",
      "lower_to": "predicate"
    },
    {
      "ir_constraint": "missing_member",
      "lower_to": "predicate"
    }
  ],
  "predicate_templates": [
    {
      "id": "pred_policy_default",
      "purpose": "bind default denylist artifact"
    },
    {
      "id": "pred_policy_check",
      "purpose": "bind membership check"
    },
    {
      "id": "pred_missing_required_member",
      "purpose": "prove missing blocked member"
    }
  ],
  "select_template": {
    "anchor": "policy_default",
    "message": "Security policy default is incomplete and does not block required member"
  }
}
```

---

**十二、L2 到 L4 的映射规则**

建议固定一套 lowering 规则。

1. `entity.kind = subject|policy|check`
   映射成 CodeQL 中的绑定 predicate

2. `relation.type = flows_to`
   映射成 DataFlow/TaintTracking predicate

3. `relation.type = uses_policy|checks|protects`
   映射成结构 join predicate，不一定用数据流

4. `constraint.kind = missing_member`
   映射成值约束 predicate

5. `guard`
   映射成 `not exists` 或正向 completeness 条件

6. `environment_condition`
   默认不强制编译成静态谓词，可作为 message 或 refinement hint
   除非代码中能静态证明

---

**十三、什么时候用 `source/sink/sanitizer`**

不要在所有 Schema IR 中全局强制。

建议改成可选视图：

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

规则：

- 只有 `pattern_type = taint_flow` 时必填
- `missing_validation` 和 `incomplete_security_policy` 可不填
- 这样不会把非污点漏洞硬塞成污点模型

---

**十四、推荐的目录与文件组织**

每个 CVE 下建议从 2 个文件扩成 4 个文件：

- `cve_facts.json`
- `schema_ir.json`
- `query_construction_steps.json`
- `backend_codeql.json`

对应四层。

---

**十五、一个最小规范总结**

如果你要正式实现，我建议把每层的“必填字段”固定成：

`L1 Fact`
- `case_id`
- `metadata`
- `code_facts`
- `patch_facts`

`L2 Schema IR`
- `pattern_type`
- `entities`
- `relations`
- `constraints`
- `guards`

`L3 Query Construction Steps`
- `goal`
- `steps`
- 每个 step: `semantic_unit/description/l2_refs/retrieval_hints/expected_output`

`L4 Backend Lowering`
- `backend`
- `query_kind`
- `imports`
- `ir_to_predicate_map`
- `select_template`

---

**十六、对你当前项目的直接建议**

你现在最适合先做这三件事：

1. 先把 `schema_ir` 改成“按 `pattern_type` 分型”的结构。
2. 把 `logic_steps` 改成“语义单元 step + 检索提示 + 期望片段输出”的结构。
3. 新增一个 `backend_codeql.json`，专门放 CodeQL query kind、imports、predicate 生成规则。

如果你愿意，我下一步可以直接帮你把 `cves/CVE-2025-27818/` 下这两个现有 JSON 重写成这套四层格式的具体样例。
