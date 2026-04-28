# Agent 诊断 + 策略约束修复（Policy-Constrained Repair）设计

## 1. 目标与范围

本文档给出一套可落地的闭环方案：由 `valid` 阶段产生的编译/运行/评估信号触发修复，但修复不是“自由文本重试”，而是：

- **Diagnoser Agent**：基于验证信号输出结构化诊断（failure type + 证据 + 修复提议）。
- **UpdateEngine（策略执行器）**：只允许在有限动作白名单内应用修复补丁（patch），并做 schema/path 约束校验。
- **RegenPlanner（重生成计划器）**：根据动作影响范围选择性重跑 `L1/L2/L3/fragments/compose`。
- **Fallback（兜底）**：当诊断不确定或策略空间不足时，执行软重置/全重置。

注意：本方案强调“可控、可复现、可审计”，不依赖 JSON 行号，所有定位使用 JSON Pointer（例如 `/guards/0`）。

---

## 2. 分层闭环（高层流程）

```text
Gen (fragments + compose)
  -> Validate (compile + run vuln/fixed + eval)
     -> Diagnoser Agent (structured diagnosis + proposed actions)
        -> UpdateEngine (validate + apply whitelisted patches)
           -> RegenPlanner (selective regeneration plan)
              -> Gen/Plan rerun as needed
                 -> Validate ...
```

核心原则：

- Agent **只提议**动作，不直接任意改 `L1/L2/L3` 文件。
- UpdateEngine **只执行**白名单动作，并强制校验。
- 当无法映射到白名单动作时，不做“自由修改”，而是走兜底策略。

---

## 3. 工件（Artifacts）

建议每轮在 `<ir_case_dir>/feedback_loop/iter_xx/` 落盘：

- `validation_summary.json`：compile/run/eval 汇总
- `diagnosis_report.json`：Diagnoser Agent 输出
- `update_actions.json`：UpdateEngine 可执行动作列表
- `regen_plan.json`：选择性重生成计划
- `updated_l1.json` / `updated_l2.json` / `updated_l3.json`：应用更新后的 IR 快照
- `state_trace.jsonl`：状态机轨迹（可选但强烈建议）

---

## 4. Diagnoser Agent 输出格式（建议）

Diagnoser 输出必须是严格 JSON（建议配 JSON Schema 校验），其任务是将低层信号映射为结构化诊断与“补丁提议（patch proposal）”。

### 4.1 `diagnosis_report.json` 示例

```json
{
  "case_id": "CVE-2025-xxxx",
  "iteration": 2,
  "primary_failure_type": "false_positive_on_fixed",
  "confidence": 0.86,
  "evidence": {
    "compile_success": true,
    "vuln_hits": 5,
    "fixed_hits": 3,
    "compile_stderr_snippet": "",
    "run_errors": [],
    "diff_signals": ["fix_added_guard"]
  },
  "suspected_layers": ["L2", "L3"],
  "proposed_patches": [
    {
      "file": "L2_schema_ir.json",
      "op": "append",
      "path": "/guards",
      "value": {
        "guard_kind": "validation_present",
        "subject": "input",
        "validation": "isValid",
        "evidence_ref": "diff: added isValid(input)"
      },
      "reason": "fixed side also matches; likely missing modeling of fix-introduced validation guard"
    }
  ]
}
```

约束（避免引入复杂 DSL，保持极简）：

- patch 只允许使用有限的 `op`：`append` / `replace` / `merge` / `remove`。
- patch 只允许修改允许的 `file + path`（第 6 节的路径白名单）。
- `confidence` 过低时应输出 `unknown_failure`，并尽量不产出结构性破坏 patch（例如改 `pattern_type`）。

---

## 5. UpdateEngine 的“极简结构化补丁”（Minimal Patch）+ 示例

UpdateEngine 接收 `diagnosis_report.json` 或 agent 的 patch 提议，转换为可执行的 `update_actions.json`（本质是 patch 列表）。

### 5.0 `update_actions.json` 通用结构（极简）

每条 patch 只保留最必要字段：

- `file`：要修改的 JSON 文件（`L1_fact.json` / `L2_schema_ir.json` / `L3_logic_plan.json` / `fragment_bundle.json` / `final_query.json`）
- `op`：有限操作（`append` / `replace` / `merge` / `remove`）
- `path`：JSON Pointer 路径（例如 `/guards`、`/constraints/0`）
- `value`：写入内容（当 `op` 需要时）
- `precondition`：可选，防误改（例如“旧值必须等于 X 才允许 replace”）
- `reason`：可选，便于审计与论文写作

```json
{
  "case_id": "CVE-2025-xxxx",
  "iteration": 2,
  "patches": [
    {
      "patch_id": "p_001",
      "file": "L2_schema_ir.json",
      "op": "append",
      "path": "/guards",
      "value": {
        "guard_kind": "validation_present",
        "subject": "input",
        "validation": "isValid",
        "evidence_ref": "diff: added isValid(input)"
      },
      "reason": "Model fix-introduced validation guard in L2 so L3 can add exclusion/constraint steps."
    }
  ]
}
```

### 5.1 示例：Composer 层修 import/组装

适用失败：

- compile 报错缺 import / namespace
- 合成冲突（重复 import、符号重名）但 fragments 本身可用

允许修改：

- `final_query.json` 的 `required_imports` 或 `query_code` 中 import 区块

示例：

```json
{
  "patch_id": "p_fix_imports_01",
  "file": "final_query.json",
  "op": "merge",
  "path": "/required_imports",
  "value": ["import semmle.code.java.*"],
  "reason": "compile stderr indicates missing Java stdlib import"
}
```

### 5.2 示例：Fragment 层重生成指定 step 片段

适用失败：

- `unresolved_codeql_symbol`
- `wrong_predicate_arity`
- `wrong_type_constraint`
- 某个 step 的 fragment 明显幻觉

允许修改（极简做法）：

- 在 `fragment_bundle.json` 写入 `regen_steps`，由生成器按 step_id 选择性重生成

示例（标记 step 需要重生成）：

```json
{
  "patch_id": "p_regen_frag_01",
  "file": "fragment_bundle.json",
  "op": "append",
  "path": "/regen_steps",
  "value": {
    "step_id": "step_locate_callsite",
    "ban_symbols": ["MethodAccess"],
    "prefer_symbols": ["MethodCall", "Call"],
    "reason": "compile stderr: could not resolve type MethodAccess"
  },
  "reason": "Regenerate only the failing fragment step."
}
```

### 5.3 示例：L3 增强检索提示（减少 API 幻觉）

适用失败：

- `retrieval_miss`：生成反复用错类/谓词/写法
- 多轮修 fragment 不稳定，怀疑检索目标过窄

允许修改：

- `L3_logic_plan.json` 的 `steps[i].retrieval_hints`（增量）

示例：

```json
{
  "patch_id": "p_aug_retr_01",
  "file": "L3_logic_plan.json",
  "op": "merge",
  "path": "/steps/2/retrieval_hints",
  "value": {
    "keywords_add": ["MethodCall qualifier", "receiver expression"],
    "candidate_classes_add": ["MethodCall", "Call"],
    "candidate_predicates_add": ["getQualifier"]
  },
  "reason": "Repeated API hallucination suggests retrieval hints are too weak/narrow."
}
```

### 5.4 示例：L3 新增一个 logic step（例如 fixed exclusion）

适用失败：

- `empty_result_on_vulnerable`，推断缺少绑定/约束/报告步骤
- `false_positive_on_fixed`，需要 exclusion step

允许修改：

- `L3_logic_plan.json` 的 `steps`（append）

示例（新增 fixed exclusion 的 where_clause step）：

```json
{
  "patch_id": "p_add_step_01",
  "file": "L3_logic_plan.json",
  "op": "append",
  "path": "/steps",
  "value": {
    "step_id": "step_exclude_when_guard_present",
    "fragment_type": "where_clause",
    "description": "Exclude cases where the fixed-side validation guard is present.",
    "requires_symbols": ["targetAction"],
    "produces_symbols": [],
    "retrieval_hints": {
      "keywords": ["guard present", "negation", "exclude fixed behavior"]
    }
  },
  "reason": "Need an explicit exclusion step to avoid false positives on fixed."
}
```

### 5.5 示例：L3 拆分过大的 step

适用失败：

- `bad_step_decomposition`
- step 同时承担 bind + constraint + reporting，导致片段复杂易错

允许修改：

- `L3_logic_plan.json` 的某一个 `steps[i]` 替换为多个 steps（需要 UpdateEngine 具备“replace-with-many”的实现）

示例（replace steps[i] 为三步）：

```json
{
  "patch_id": "p_split_step_01",
  "file": "L3_logic_plan.json",
  "op": "replace",
  "path": "/steps/4",
  "value": [
    {
      "step_id": "step_bind_target_call",
      "fragment_type": "predicate",
      "produces_symbols": ["targetCall"]
    },
    {
      "step_id": "step_check_missing_guard",
      "fragment_type": "where_clause",
      "requires_symbols": ["targetCall"]
    },
    {
      "step_id": "step_reporting_anchor",
      "fragment_type": "select_clause",
      "requires_symbols": ["targetCall"]
    }
  ],
  "reason": "Split an oversized step into bind/check/report to improve stability."
}
```

### 5.6 示例：L2 新增 guard/validation 语义

适用失败：

- `false_positive_on_fixed` 且 diff 显示 fix 添加了校验/guard
- 需要在 L2 显式表达“应存在的 guard”

允许修改：

- `L2_schema_ir.json` 的 `guards`（append）

示例：

```json
{
  "patch_id": "p_add_guard_01",
  "file": "L2_schema_ir.json",
  "op": "append",
  "path": "/guards",
  "value": {
    "guard_kind": "validation_present",
    "subject": "pathParam",
    "validation": "normalizeAndRejectTraversal",
    "evidence_ref": "diff: added normalizeAndRejectTraversal(pathParam)"
  },
  "reason": "Fixed-side added validation; model it in L2 so downstream can exclude fixed behavior."
}
```

### 5.7 示例：L2 补齐语义实体/关系（entity / relation）

适用失败：

- `empty_result_on_vulnerable` 且 diagnoser 判断缺关键实体/关系导致无法绑定

允许修改：

- `L2_schema_ir.json` 的 `entities` / `relations`（append）

示例（新增 entity）：

```json
{
  "patch_id": "p_add_entity_01",
  "file": "L2_schema_ir.json",
  "op": "append",
  "path": "/entities",
  "value": {
    "entity_id": "PathArg",
    "entity_kind": "argument",
    "description": "user-controlled filesystem path argument",
    "evidence_ref": "diff: modified method taking String path"
  },
  "reason": "Missing entity prevents binding the vulnerable argument in L3."
}
```

示例（新增 relation）：

```json
{
  "patch_id": "p_add_relation_01",
  "file": "L2_schema_ir.json",
  "op": "append",
  "path": "/relations",
  "value": {
    "relation_kind": "flows_to",
    "from": "PathArg",
    "to": "FileAccessCall",
    "evidence_ref": "diff: path passed into file open call"
  },
  "reason": "Missing relation prevents constructing the core constraint in L3."
}
```

### 5.8 示例：L2 切换 pattern_type（高风险，需门槛）

适用失败（必须高门槛）：

- 多轮失败表现为“taint-flow 不成立”，但 diff/evidence 明确是策略不完整或缺 guard
- diagnoser 置信度高且重复出现

允许修改：

- 仅允许替换 `L2.pattern_type`，并记录 evidence；触发后强制全量重建 L2/L3

示例：

```json
{
  "patch_id": "p_change_pattern_01",
  "file": "L2_schema_ir.json",
  "op": "replace",
  "path": "/pattern_type",
  "value": "incomplete_security_policy",
  "precondition": {
    "path": "/pattern_type",
    "in": ["taint_flow", "missing_validation", "unsafe_default", "authorization_bypass", "state_or_lifecycle_violation"]
  },
  "reason": "Repeated failures suggest mis-modeled vulnerability pattern; switch to policy completeness."
}
```

### 5.9 示例：L1 修正事实层关键字段（保守）

适用失败：

- 软重置后仍失败，怀疑 L1 对关键位置/符号抽取错误

允许修改：

- 仅允许替换/追加少量关键事实字段（避免 agent 重写整份 L1）

示例：

```json
{
  "patch_id": "p_revise_fact_01",
  "file": "L1_fact.json",
  "op": "replace",
  "path": "/vuln_location/method",
  "value": "endHandler",
  "precondition": {
    "path": "/vuln_location/method",
    "equals": "startHandler"
  },
  "reason": "Correct a mis-extracted method name so replanning can anchor properly."
}
```

---

## 6. UpdateEngine 必须执行的约束（防“自由修改”）

为了保证动作白名单具有实际意义，UpdateEngine 应包含三道闸门：

### 6.1 动作白名单校验

- 为避免引入复杂 DSL，这里不要求 `action_type` 枚举。
- White-list 的最小实现是：
  - `op` 必须在允许集合：`append` / `replace` / `merge` / `remove`
  - `file` 必须在允许集合：`L1_fact.json` / `L2_schema_ir.json` / `L3_logic_plan.json` / `fragment_bundle.json` / `final_query.json`
  - `path` 必须落在该文件的 allowed paths 集合中（下一节）

### 6.2 路径白名单（Allowed Paths）

即使 `op/file` 合法，也必须限制可改字段路径。

为避免在论文里引入复杂 DSL，这里建议把 allowed paths 抽成一个极简配置文件，让 UpdateEngine 直接读取并校验：

- `patch_policy.yaml`

配置文件只约束三件事：`file`、`op`、`path`（JSON Pointer 前缀/通配符），不引入额外语义。

下方仅保留一个“示例级”说明（真实权威列表以 `patch_policy.yaml` 为准，可按项目演化调整）：

- L1 允许：`/vuln_location/*`、`/key_symbols/*`、`/assumptions/-`
- L2 允许：`/pattern_type`、`/entities`、`/relations`、`/constraints`、`/guards`、`/reporting`
- L3 允许：`/steps`、`/steps/*/retrieval_hints`、`/steps/*/requires_symbols`、`/steps/*/produces_symbols`

### 6.3 Schema 校验

- 应用 patch 后，必须校验 JSON 仍符合 L1/L2/L3 schema（字段类型、必填项）。
- 校验失败：拒绝写回，回退到上一版本，并触发兜底策略。

---

## 7. RegenPlanner：动作到重跑范围的映射

建议用基于“修改了哪个文件”的固定映射（更简单、无需 DSL）：

- `final_query.json` -> `RERUN_COMPOSER_ONLY`
- `fragment_bundle.json` -> `RERUN_FRAGMENTS`（单 step 或依赖子图）+ `compose`
- `L3_logic_plan.json` -> `RERUN_L3` + fragments + compose
- `L2_schema_ir.json` -> `RERUN_L2_L3` + fragments + compose
- `L1_fact.json` -> `RERUN_L1_L2_L3` + fragments + compose

---

## 8. 兜底策略（A 方案）：软重置与全重置

白名单不可能覆盖所有长尾复杂情况，因此必须有保守兜底。

### 8.1 软重置：`fallback_replan_from_l1`

含义：

- 保留 `L1_fact.json`
- 丢弃当前 `L2/L3/fragments/final query` 的派生链
- 从 `L1 -> L2 -> L3 -> Gen -> Validate` 重新开始

适用：

- 连续局部修补无改善
- 或未知失败连续出现，但仍认为 L1 事实可信

### 8.2 全重置：`fallback_full_replan_from_inputs`

含义：

- 丢弃 `L1/L2/L3/fragments/query`
- 回到最原始输入（CVE 描述、diff、repo）重新规划

适用：

- 软重置后仍失败
- 或高度怀疑 L1 事实抽取错误

### 8.3 最小可实现触发规则（建议）

- 连续 2 次 `unknown_failure` -> `fallback_replan_from_l1`
- 软重置后再失败 -> `fallback_full_replan_from_inputs`
- 连续 3 次局部修补无改善 -> `fallback_replan_from_l1`

---

## 9. 为什么此方案在学术上更“方法化”

相较于“直接让 agent 改 query 或改 JSON 并重试”，本方案的关键差异在于：

- **结构化诊断**：失败原因以统一 failure taxonomy 表达，而不是日志拼接。
- **受限动作空间**：修复以有限动作集合表达，支持消融与复现。
- **选择性重生成**：按依赖范围重跑，避免全量重试带来的噪声与成本。
- **保守兜底**：白名单不完备时仍可收敛，不会卡死。

---

## 10. 实现建议（最小版本）

建议先实现 MVP：

- 动作：`FIX_COMPOSE_IMPORTS`、`REGENERATE_FRAGMENT`、`AUGMENT_RETRIEVAL_HINTS`、`ADD_GUARD`、`ADD_STEP`、`CHANGE_PATTERN_TYPE`、`unknown_failure`
- 兜底：软重置 + 全重置（按第 8.3 的三条规则）
- 校验：动作白名单 + 路径白名单 + 基本 schema 校验

这样就能在工程上跑起来，并且足以支撑论文里的“policy-constrained repair”主张。
