# VulnSynth 分层反馈闭环与显式更新规则设计

## 1. 目标

本文档设计一套适用于 `VulnSynth` 的显式反馈闭环方案，用于将 CodeQL query 的编译、执行、评估失败信号回写到前面的 `plan agent` 产物中，而不是只在最终 query 层做局部修补。

核心目标是把反馈从“黑盒字符串提示”升级为“结构化诊断 -> 结构化更新 -> 分层重生成”流程，使失败信号能够作用于以下层次：

- `L1`：事实层，修正缺失或错误的 case facts
- `L2`：语义层，修正 `pattern_type`、实体、关系、约束、guard
- `L3`：构造层，修正 step 切分、step 顺序、符号依赖、检索提示
- `Fragment`：修正单个 step 的 lowering 片段
- `Composer`：修正最终 query 的组装方式

---

## 2. 总体闭环

建议将完整闭环抽象为如下状态迁移：

```text
Case Inputs
  -> Plan Agent
     -> L1
     -> L2
     -> L3
  -> Gen Agent
     -> Step Fragments
     -> Final Query
  -> Validator
     -> Compile Result
     -> Run Result (vuln/fixed)
     -> Evaluation Result
  -> Failure Analyzer
     -> Structured Failure Report
  -> Update Engine
     -> Update Actions on L1/L2/L3/Fragments/Composer
  -> Selective Regeneration
     -> Re-run affected stages only
```

这个闭环的关键点不是“失败后再试一次”，而是：

- 先把失败原因分类
- 再把不同失败映射到不同层级
- 最后按层级做最小必要更新，而不是每轮都从头生成全部内容

---

## 3. 核心设计原则

### 3.1 分层最小修复

每次失败优先修复离错误最近的层：

- 语法、import、类型错误：先修 `Fragment` 或 `Composer`
- 语义缺件、guard 缺失、关系建模错误：修 `L2` 和 `L3`
- 检索目标错、候选类/谓词错：修 `L3.retrieval_hints`
- 漏洞事实遗漏、修复证据理解错：回写 `L1`

### 3.2 显式升级策略

同一类错误连续出现时，才逐层向前升级：

- 第 1 次：局部修 `Composer` 或 `Fragment`
- 第 2 次：升级到 `L3`
- 第 3 次：升级到 `L2`
- 第 4 次及以上：怀疑 `L1` 或 case interpretation 根本有问题

### 3.3 失败类型与更新规则解耦

失败分析器只负责给出：

- 失败类型
- 证据
- 置信度
- 建议更新层级

真正如何修改 `L1/L2/L3`，由 Update Engine 按规则执行。

### 3.4 可落盘、可审计

每轮失败都应生成结构化文件，避免“只有 prompt 历史，没有方法状态”：

- `failure_report.json`
- `update_actions.json`
- `updated_l1.json` / `updated_l2.json` / `updated_l3.json`
- `regen_plan.json`

---

## 4. 建议新增的数据结构

## 4.1 `failure_report.json`

```json
{
  "case_id": "CVE-2025-27818",
  "iteration": 2,
  "query_path": "src/IR/CVE-2025-27818/generated_query/CVE-2025-27818.ql",
  "compile": {
    "success": false,
    "stderr_summary": "Could not resolve type MethodAccess"
  },
  "execution": {
    "ran_on_vulnerable": false,
    "ran_on_fixed": false,
    "vulnerable_results": 0,
    "fixed_results": 0
  },
  "evaluation": {
    "recall_method": false,
    "recall_file": false,
    "false_positive_on_fixed": false
  },
  "classified_failures": [
    {
      "failure_type": "unresolved_codeql_symbol",
      "severity": "high",
      "confidence": 0.96,
      "evidence": [
        "compile stderr contains 'could not resolve type'",
        "error appears in fragment step_locate_policy_check"
      ],
      "suggested_update_scope": [
        "fragment",
        "l3_retrieval"
      ]
    }
  ]
}
```

## 4.2 `update_actions.json`

```json
{
  "case_id": "CVE-2025-27818",
  "iteration": 2,
  "actions": [
    {
      "action_id": "act_001",
      "target_layer": "L3",
      "target_object_id": "step_locate_policy_check",
      "action_type": "augment_retrieval_hints",
      "reason": "Unresolved CodeQL symbol indicates wrong candidate classes/predicates",
      "patch": {
        "candidate_classes_add": ["MethodCall", "Call"],
        "candidate_predicates_add": ["getCallee", "getArgument"]
      }
    },
    {
      "action_id": "act_002",
      "target_layer": "Fragment",
      "target_object_id": "step_locate_policy_check",
      "action_type": "regenerate_fragment",
      "reason": "Existing fragment uses unknown APIs"
    }
  ]
}
```

## 4.3 `regen_plan.json`

```json
{
  "case_id": "CVE-2025-27818",
  "iteration": 2,
  "rerun_scope": {
    "rerun_l1": false,
    "rerun_l2": false,
    "rerun_l3": true,
    "rerun_steps": [
      "step_locate_policy_check"
    ],
    "rerun_composer": true
  },
  "reason": "L3 retrieval hints and dependent fragment changed"
}
```

---

## 5. 失败类型体系

建议把失败分类固定为以下几类。注意这里的失败类型不是日志文本，而是框架内部统一语义标签。

### 5.1 编译类失败

- `syntax_error`
- `missing_import`
- `unresolved_codeql_symbol`
- `wrong_predicate_arity`
- `wrong_type_constraint`
- `fragment_composition_conflict`

### 5.2 执行类失败

- `query_runtime_failure`
- `database_analyze_failure`
- `empty_result_on_vulnerable`
- `unexpected_result_explosion`

### 5.3 效果类失败

- `target_miss_on_vulnerable`
- `false_positive_on_fixed`
- `weak_reporting_anchor`
- `incomplete_path_explanation`

### 5.4 规划类失败

- `wrong_pattern_type`
- `missing_semantic_entity`
- `missing_guard_or_constraint`
- `bad_step_decomposition`
- `bad_symbol_interface`
- `retrieval_miss`
- `retrieval_over_bias`

---

## 6. 显式更新规则矩阵

以下是最关键的部分：把失败类型显式映射到前面 plan agent 各层的更新动作。

## 6.1 编译失败 -> 优先修 Fragment / Composer，重复后升级到 L3

### 规则 R1：`syntax_error`

触发条件：

- `codeql query compile` 失败
- stderr 中主要为语法解析错误

更新动作：

- 首先只更新 `Composer.query_code` 的拼接方式
- 不修改 `L1/L2`
- 若同一 step 连续 2 次产生语法错误，则在 `L3` 中为该 step 增加更强的 `expected_output` 约束

显式 patch：

- `Fragment.notes` 增加失败教训
- `L3.steps[i].expected_output` 增补“must return a single valid predicate body”之类约束

### 规则 R2：`missing_import`

触发条件：

- 编译错误表现为缺失模块、类或 namespace

更新动作：

- 更新 `Fragment.required_imports`
- 更新 `Composer.required_imports`
- 不直接改 `L2`

升级条件：

- 若连续两轮仍缺同类 import，说明 step 检索不足，升级更新 `L3.retrieval_hints.candidate_classes`

### 规则 R3：`unresolved_codeql_symbol`

触发条件：

- 使用了不存在的类、谓词、方法

更新动作：

- 更新目标 step 的 `L3.retrieval_hints`
- 为该 step 附加 `symbol_correction_note`
- 重新生成该 step fragment

升级条件：

- 若同一语义单元连续 2 次 unresolved，回写 `L2`，检查实体/关系是否对应了错误的 CodeQL 建模目标

### 规则 R4：`fragment_composition_conflict`

触发条件：

- 单个 fragment 各自合理，但组装后存在重名、重复定义、循环依赖、`where/select` 锚点冲突

更新动作：

- 只更新 `Composer`
- 若冲突来自 symbol interface 不一致，则回写 `L3.requires_symbols` / `produces_symbols`

---

## 6.2 vuln 侧无结果 -> 优先怀疑 L3/L2，而不是只修 query 文本

### 规则 R5：`empty_result_on_vulnerable`

触发条件：

- query 编译成功
- vulnerable 数据库结果为 0

诊断拆分：

- 若 query 结构与目标语义明显一致，但约束太严格，判为 `over_constrained_query`
- 若关键 target method/file 一个都没碰到，判为 `target_miss_on_vulnerable`
- 若定位用的类/谓词明显错，判为 `retrieval_miss`

更新动作：

- 优先更新 `L3`
- 检查是否缺少“定位漏洞锚点”的 step
- 检查 `retrieval_hints` 是否过窄
- 检查 `requires_symbols` 是否导致后续 step 使用了未绑定符号

升级条件：

- 若补充 step 后仍完全 miss，则回写 `L2`，增加缺失实体或关系

### 规则 R6：`target_miss_on_vulnerable`

触发条件：

- query 有结果，但无法覆盖 vuln 版本中的目标方法/文件

更新动作：

- 若报告锚点错：更新 `L2.reporting`
- 若危险动作未建模：更新 `L2.entities` 和 `L2.relations`
- 若缺辅助谓词：在 `L3` 新增 step，例如：
  - `step_bind_target_action`
  - `step_restrict_target_context`

---

## 6.3 fixed 侧误报 -> 优先修 L2 guard/constraint 与 L3 exclusion step

### 规则 R7：`false_positive_on_fixed`

触发条件：

- vulnerable 命中目标
- fixed 也命中目标，或命中很多等价点

更新动作：

- 回写 `L2.guards`
- 回写 `L2.constraints`
- 在 `L3` 增加或强化下面类型的 step：
  - sanitizer / guard 检测 step
  - exclusion predicate step
  - refined reporting anchor step

推荐操作：

- 如果 fix 引入的是新 validation，优先在 `L2` 新增 `guard`
- 如果 fix 引入的是新 policy member，优先在 `L2` 新增 `missing_member` 与 `contains_member` 对偶建模
- 如果 fix 只是额外上下文约束，优先在 `L3` 增加 `where_clause` step

### 规则 R8：`weak_reporting_anchor`

触发条件：

- query 能检测到问题，但报告位置不稳定或不指向核心漏洞点

更新动作：

- 只更新 `L2.reporting`
- 同时更新 `L3` 中产生 anchor symbol 的 step

---

## 6.4 检索失败 -> 显式回写 L3 检索计划

### 规则 R9：`retrieval_miss`

触发条件：

- 生成片段多次调用不存在 API
- 片段模式明显偏离该语言常见 CodeQL 写法
- 检索结果和 step 语义单元不匹配

更新动作：

- 修改 `L3.steps[i].retrieval_hints.keywords`
- 修改 `candidate_classes`
- 修改 `candidate_predicates`
- 修改 `reference_query_patterns`
- 修改 `build_step_retrieval_plan()` 产出的 `collection_query_map`

推荐显式规则：

- `predicate` / `helper_class` 类型 step 优先强化 `symbol_query`
- `where_clause` / `select_clause` 类型 step 优先强化 `semantic_query` 和 `pattern_query`
- 连续两轮 API 幻觉时，将 `need_cwe_semantics` 降低，改为优先检索本语言 `local_queries` 和 `stdlib`

### 规则 R10：`retrieval_over_bias`

触发条件：

- 检索结果让生成过度贴近某个参考 query，导致 query 与当前 case 不匹配

更新动作：

- 降低 `reference_query_patterns` 权重
- 增加 case-specific `semantic_query`
- 在 step 中增加 `notes`，强调“adapt pattern, do not copy”

---

## 6.5 规划错误 -> 回写 L2/L1

### 规则 R11：`wrong_pattern_type`

触发条件：

- 当前被建模为 `taint_flow`，但多轮失败都表现为“真正需要的是 policy completeness / missing validation / unsafe default”

更新动作：

- 直接回写 `L2.pattern_type`
- 根据新的 `pattern_type` 重新生成整个 `L2`
- 废弃旧 `L3`
- 全量重建 step 集

这是最强的一类更新，应谨慎触发。建议条件：

- 至少两轮失败
- 且失败分析器置信度高
- 且多个失败信号共同支持模式错判

### 规则 R12：`missing_semantic_entity`

触发条件：

- fragment 或 composer 多次需要某个对象，但 `L2.entities` 中不存在

更新动作：

- 在 `L2.entities` 中显式新增实体
- 为其补 `evidence_refs`
- 在 `L3` 新增 bind step

### 规则 R13：`missing_guard_or_constraint`

触发条件：

- false positive 或 target miss 可归因于缺 guard / constraint

更新动作：

- 在 `L2.constraints` 或 `L2.guards` 中增加对象
- 在 `L3` 增加实现该 guard 的 step

### 规则 R14：`bad_step_decomposition`

触发条件：

- 单个 step 过大，既负责定位实体又负责报告又负责 exclusion
- 或多个 step 之间符号接口模糊，导致重生成时经常冲突

更新动作：

- 重写 `L3.steps`
- 把大 step 拆成：
  - bind step
  - refine step
  - guard step
  - reporting step

---

## 7. 分层更新策略

为了避免每次失败都全量回滚，建议定义一套标准升级路径。

## 7.1 默认更新路径

```text
Composer -> Fragment -> L3 -> L2 -> L1
```

## 7.2 升级门槛

- `Composer` 连续失败 2 次：升级到 `L3`
- 同一 step fragment 连续失败 2 次：升级到 `L3`
- 不同 step 因同一语义错误连续失败 2 次：升级到 `L2`
- `pattern_type` 相关失败连续 2 次且评估一致：升级重建 `L2`
- 若修复证据与漏洞事实本身被误读：升级到 `L1`

## 7.3 回退规则

若某次前层重写导致效果更差，则允许回退到上一个稳定版本：

- 保留每轮 `L1/L2/L3` 快照
- `regen_plan.json` 中标记 `base_version`
- 支持“从稳定 L2 + 新 L3”继续，而不是强制沿最新状态推进

---

## 8. 推荐的 Failure Analyzer 输出逻辑

建议 Failure Analyzer 按固定顺序工作：

### 8.1 第一步：收集信号

输入：

- `compile_result.json`
- vulnerable / fixed 执行结果
- SARIF
- evaluator summary
- 最终 query
- fragment bundle
- `L1/L2/L3`

### 8.2 第二步：做诊断判断

生成：

- 主失败类型 `primary_failure`
- 次失败类型 `secondary_failures`
- 证据列表 `evidence`
- 更新建议 `suggested_update_scope`

### 8.3 第三步：写显式动作

转换成 `update_actions.json`

每个 action 必须指明：

- 目标层
- 目标对象
- 动作类型
- 触发原因
- 预期影响范围

---

## 9. Update Engine 的显式动作集合

建议把 Update Engine 的动作限制在有限集合内，避免变成不透明自由文本。

## 9.1 对 L1 的动作

- `append_fact`
- `revise_fact`
- `raise_fact_confidence`
- `lower_fact_confidence`
- `attach_new_evidence_ref`

## 9.2 对 L2 的动作

- `change_pattern_type`
- `add_entity`
- `revise_entity`
- `add_relation`
- `revise_relation`
- `add_constraint`
- `add_guard`
- `revise_reporting`

## 9.3 对 L3 的动作

- `add_step`
- `remove_step`
- `split_step`
- `merge_steps`
- `revise_step_description`
- `augment_retrieval_hints`
- `revise_symbol_interface`
- `change_fragment_type`

## 9.4 对生成层的动作

- `regenerate_fragment`
- `regenerate_fragments_by_dependency`
- `recompose_query`
- `fallback_to_previous_fragment`

---

## 10. 选择性重生成策略

建议按 action 类型决定重生成范围。

### 10.1 仅重组装

触发：

- `missing_import`
- `fragment_composition_conflict`
- `weak_reporting_anchor`

执行：

- 不重跑 plan
- 不重生 fragment
- 仅重跑 composer

### 10.2 单 step 重生成

触发：

- `unresolved_codeql_symbol`
- `wrong_predicate_arity`
- `retrieval_miss`

执行：

- 更新目标 step 的 `L3`
- 只重跑目标 step fragment
- 重跑 composer

### 10.3 子图重生成

触发：

- 某 step 改动影响多个依赖 step

执行：

- 从被修改 step 开始，沿 `produces_symbols -> requires_symbols` 依赖图向后传播
- 只重跑受影响 step
- 重跑 composer

### 10.4 全量 L3 重建

触发：

- `bad_step_decomposition`
- `missing_semantic_entity`

执行：

- 保留 `L1/L2`
- 全量重建 `L3`
- 全量重生 fragments
- 重跑 composer

### 10.5 全量 L2/L3 重建

触发：

- `wrong_pattern_type`
- `missing_guard_or_constraint` 且影响全局语义

执行：

- 重新生成 `L2`
- 重新生成 `L3`
- 全量重生 fragments
- 重跑 composer

---

## 11. 推荐的落盘目录结构

建议每轮在 case 目录下增加：

```text
src/IR/<CVE>/feedback_loop/
  iter_01/
    failure_report.json
    update_actions.json
    regen_plan.json
    updated_l1.json
    updated_l2.json
    updated_l3.json
    notes.md
  iter_02/
    ...
```

如果要和现有 `generated_query/` 对齐，也可采用：

```text
src/IR/<CVE>/
  codeql_schema_ir.json
  codeql_logic_steps.json
  generated_query/
  feedback_loop/
```

---

## 12. 与当前代码结构的集成建议

可在当前项目中增加以下组件：

- 在 `src/vulnsynth.py` 外围增加 `FeedbackLoopController`
- 在 `src/query_subagents_evaluation.py` 复用 compile/run/eval 能力
- 新增 `src/feedback_analyzer.py`
- 新增 `src/update_engine.py`
- 新增 `src/regen_planner.py`

推荐接口：

```python
class FeedbackLoopController:
    async def run_iteration(self, case_dir: str, query_path: str) -> dict: ...

class FailureAnalyzer:
    def analyze(self, compile_result: dict, execution_result: dict, evaluation_result: dict,
                l1: dict, l2: dict, l3: dict, fragment_bundle: dict) -> dict: ...

class UpdateEngine:
    def apply_actions(self, l1: dict, l2: dict, l3: dict, actions: dict) -> tuple[dict, dict, dict]: ...

class RegenPlanner:
    def build_regen_plan(self, actions: dict, l3: dict) -> dict: ...
```

---

## 13. 一个推荐的控制算法

```text
for iteration in 1..N:
  1. generate fragments and final query
  2. compile
  3. if compile fails:
       analyze failure
       write failure_report
       derive update_actions
       apply updates
       selective regenerate
       continue
  4. run on vulnerable/fixed DB
  5. evaluate
  6. if success criterion satisfied:
       stop
  7. analyze failure
  8. derive update_actions
  9. apply updates to L1/L2/L3
 10. build regen_plan
 11. selective regenerate
```

成功判定建议至少包含：

- compile success
- vulnerable 命中目标方法或目标文件
- fixed 不命中目标，或明显少于 vulnerable

---

## 14. 作为论文方法点时该怎么表述

如果后续实现了这套规则，方法上不应只说“我们加入验证闭环”，而应表述为：

- a structured failure taxonomy for CVE-to-CodeQL synthesis
- an explicit update policy over semantic IR layers
- hierarchical refinement from query-level feedback back to planning-level representations
- selective regeneration based on dependency-aware update scopes

比起普通“agent self-refinement”，这里的核心方法点是：

- 反馈不是自由文本
- 更新不是黑盒 prompt 重试
- 重生成不是无差别全量重跑

---

## 15. 最小可实现版本

如果你想先做一个 MVP，建议只实现以下 6 条规则：

- `syntax_error -> composer`
- `missing_import -> composer + fragment.required_imports`
- `unresolved_codeql_symbol -> l3.retrieval_hints + fragment regenerate`
- `empty_result_on_vulnerable -> add/revise l3 step`
- `false_positive_on_fixed -> add l2 guard + add l3 exclusion step`
- `wrong_pattern_type -> regenerate l2 + l3`

这个版本已经足够支撑论文里的“显式更新规则”主张。

---

## 16. 一句话总结

最推荐的方案是把 `VulnSynth` 的失败闭环设计成：

**验证信号先被结构化诊断，再被映射成显式的层级更新动作，最后驱动对 `L1/L2/L3/fragment/composer` 的选择性重生成。**

这样你的系统就不再只是“生成失败后重试”，而是一个真正的、带有可解释状态更新规则的分层程序综合框架。

---

## 17. 代码实现友好的状态机图

下面给出一版可直接映射到 controller 的状态机。建议你在代码里把每个状态实现成一个明确的方法，事件实现成结构化枚举。

### 17.1 状态机（文本图）

```text
[S0 INIT]
  -> (start_case) -> [S1 PLAN_READY]

[S1 PLAN_READY]
  action: load or generate L1/L2/L3
  -> (plan_ok) -> [S2 GEN_QUERY]
  -> (plan_fail) -> [S9 TERMINAL_FAIL]

[S2 GEN_QUERY]
  action: generate fragments + compose final query
  -> (gen_ok) -> [S3 VALIDATE_COMPILE]
  -> (gen_fail) -> [S5 ANALYZE_FAILURE]  # 视为 generation failure

[S3 VALIDATE_COMPILE]
  action: compile query
  -> (compile_ok) -> [S4 VALIDATE_EXEC_EVAL]
  -> (compile_fail) -> [S5 ANALYZE_FAILURE]

[S4 VALIDATE_EXEC_EVAL]
  action: run on vuln/fixed + evaluate metrics
  -> (eval_success) -> [S8 TERMINAL_SUCCESS]
  -> (eval_fail) -> [S5 ANALYZE_FAILURE]

[S5 ANALYZE_FAILURE]
  action: FailureAnalyzer -> failure_report.json
  -> (analyze_ok) -> [S6 APPLY_UPDATE]
  -> (analyze_fail) -> [S9 TERMINAL_FAIL]

[S6 APPLY_UPDATE]
  action: UpdateEngine -> update_actions.json + updated L1/L2/L3
  -> (update_ok) -> [S7 PLAN_REGEN_SCOPE]
  -> (update_fail) -> [S9 TERMINAL_FAIL]

[S7 PLAN_REGEN_SCOPE]
  action: SelectiveRegeneration -> regen_plan.json
  -> (rerun_composer_only) -> [S2 GEN_QUERY]          # composer-only mode
  -> (rerun_fragments) -> [S2 GEN_QUERY]              # step/subgraph mode
  -> (rerun_l3) -> [S1 PLAN_READY]                    # rebuild L3 then gen
  -> (rerun_l2_l3) -> [S1 PLAN_READY]                 # rebuild L2/L3 then gen
  -> (rerun_l1_l2_l3) -> [S1 PLAN_READY]              # full replanning
  -> (fallback_replan_from_l1) -> [S1 PLAN_READY]     # drop current L2/L3/query lineage
  -> (fallback_full_replan_from_inputs) -> [S0 INIT]  # restart from raw case inputs
  -> (budget_exhausted) -> [S9 TERMINAL_FAIL]

[S8 TERMINAL_SUCCESS]
  action: persist final artifacts + stop

[S9 TERMINAL_FAIL]
  action: persist final failure summary + stop
```

### 17.2 状态机实现建议

- 使用一个 `LoopState` 枚举，例如：
  - `INIT`, `PLAN_READY`, `GEN_QUERY`, `VALIDATE_COMPILE`, `VALIDATE_EXEC_EVAL`,
    `ANALYZE_FAILURE`, `APPLY_UPDATE`, `PLAN_REGEN_SCOPE`, `TERMINAL_SUCCESS`, `TERMINAL_FAIL`
- 使用一个 `FailureType` 枚举，对应本文第 5 节失败类型体系。
- 建议再增加一个 `RegenMode` 枚举，例如：
  - `RERUN_COMPOSER_ONLY`
  - `RERUN_FRAGMENTS`
  - `RERUN_L3`
  - `RERUN_L2_L3`
  - `RERUN_L1_L2_L3`
  - `FALLBACK_REPLAN_FROM_L1`
  - `FALLBACK_FULL_REPLAN_FROM_INPUTS`
- 每次状态转换都记录：
  - `from_state`
  - `event`
  - `to_state`
  - `timestamp`
  - `artifacts`
- 推荐新增 `state_trace.jsonl`，便于复现实验和论文审稿材料准备。

### 17.3 伪代码骨架（controller 级）

```python
while not terminal:
    if state == PLAN_READY:
        l1, l2, l3 = run_or_load_plan(...)
        state = GEN_QUERY
    elif state == GEN_QUERY:
        query_artifacts = run_generation(...)
        state = VALIDATE_COMPILE
    elif state == VALIDATE_COMPILE:
        compile_result = run_compile(...)
        state = VALIDATE_EXEC_EVAL if compile_result.success else ANALYZE_FAILURE
    elif state == VALIDATE_EXEC_EVAL:
        eval_result = run_eval(...)
        state = TERMINAL_SUCCESS if eval_result.success else ANALYZE_FAILURE
    elif state == ANALYZE_FAILURE:
        failure_report = analyze_failure(...)
        state = APPLY_UPDATE
    elif state == APPLY_UPDATE:
        updated_ir = apply_updates(...)
        state = PLAN_REGEN_SCOPE
    elif state == PLAN_REGEN_SCOPE:
        regen_plan = build_regen_plan(...)
        state = map_regen_plan_to_next_state(regen_plan)
```

---

## 18. 失败类型到重跑层级执行表

下表给出“失败类型 -> 更新层级 -> 重跑范围 -> 升级条件”的一览，可直接作为实现时的规则表。

| failure_type | 主更新层 | 最小重跑范围 | 升级重跑范围 | 升级条件（连续轮次） |
| --- | --- | --- | --- | --- |
| `syntax_error` | Composer | 仅重跑 composer | L3 + 相关 fragments + composer | 同类语法错误 >= 2 |
| `missing_import` | Composer + Fragment | 仅重跑 composer（必要时单 step fragment） | L3 step retrieval hints + step fragment + composer | 连续缺同类 import >= 2 |
| `unresolved_codeql_symbol` | L3 + Fragment | 单 step fragment + composer | L2 + L3 + 相关 fragments + composer | 同一语义单元 unresolved >= 2 |
| `wrong_predicate_arity` | Fragment | 单 step fragment + composer | L3 step 重写 + 子图 fragments + composer | 连续 arity 错误 >= 2 |
| `wrong_type_constraint` | Fragment 或 L2 | 单 step fragment + composer | L2 重写 + L3 重写 + 全量 fragments + composer | 连续类型约束错 >= 2 |
| `fragment_composition_conflict` | Composer（必要时 L3 symbol interface） | 仅重跑 composer | L3 symbol interface + 子图 fragments + composer | 连续冲突 >= 2 |
| `query_runtime_failure` | Fragment/Composer | 相关 step fragments + composer | L3 全量 + fragments + composer | 连续 runtime fail >= 2 |
| `database_analyze_failure` | 执行环境（非 IR） | 不重跑 Plan/Gen，先重试 Validate | 同左 | 非语义问题，通常不升级 |
| `empty_result_on_vulnerable` | L3（必要时 L2） | L3 局部修订 + 相关 fragments + composer | L2 + L3 + 全量 fragments + composer | 连续 vuln 0 结果 >= 2 |
| `target_miss_on_vulnerable` | L2 + L3 | L3 新增/修改 step + 子图 fragments + composer | L2 重写 + L3 全量 + fragments + composer | 连续 miss >= 2 |
| `false_positive_on_fixed` | L2 guard/constraint + L3 exclusion | 相关步骤 fragments + composer | L2 重写 + L3 全量 + fragments + composer | 连续 fixed 误报 >= 2 |
| `weak_reporting_anchor` | L2 reporting + L3 anchor step | anchor 相关 step + composer | L3 全量 + composer | 连续 anchor 弱 >= 2 |
| `retrieval_miss` | L3 retrieval hints | 单 step fragment + composer | L3 全量 + fragments + composer | 连续检索失配 >= 2 |
| `retrieval_over_bias` | L3 retrieval hints | 单 step fragment + composer | L3 全量 + fragments + composer | 连续模式偏置 >= 2 |
| `missing_semantic_entity` | L2 + L3 | L2 增实体 + L3 局部 + 子图 fragments + composer | L2/L3 全量 + fragments + composer | 连续缺实体 >= 2 |
| `missing_guard_or_constraint` | L2 + L3 | L2 增 guard/constraint + 子图 fragments + composer | L2/L3 全量 + fragments + composer | 连续缺 guard/constraint >= 2 |
| `bad_step_decomposition` | L3 | L3 全量 + fragments + composer | L2 + L3 + 全量 fragments + composer | 连续分解失败 >= 2 |
| `wrong_pattern_type` | L2（并牵引 L3） | L2 + L3 + 全量 fragments + composer | L1 + L2 + L3 + 全量 fragments + composer | 高置信模式错判且连续 >= 2 |
| `unknown_failure` | Fallback | `fallback_replan_from_l1` | `fallback_full_replan_from_inputs` | 未知失败或低置信分析连续 >= 2 |
| `failure_oscillation` | Fallback | `fallback_replan_from_l1` | `fallback_full_replan_from_inputs` | 最近窗口内失败类型频繁震荡 |

### 18.1 执行表使用方式

- 第一步：Failure Analyzer 输出 `primary_failure_type`。
- 第二步：在执行表中查 `主更新层` 和 `最小重跑范围`，生成 `update_actions.json` 与 `regen_plan.json`。
- 第三步：检查该失败在最近窗口中的连续计数，若达到门槛则采用 `升级重跑范围`。
- 第四步：写入本轮状态轨迹与工件快照，进入下一轮。

### 18.2 预算与终止条件建议

建议引入以下预算，防止无限循环：

- `max_total_iterations`
- `max_same_failure_repeats`
- `max_full_replans`（L2/L3 或 L1/L2/L3 全量重建次数）
- `max_fallback_replans_from_l1`
- `max_full_resets_from_inputs`

达到预算时进入 `TERMINAL_FAIL`，并落盘：

- `final_failure_summary.json`
- `state_trace.jsonl`
- 最后一次 `failure_report.json`

---

## 19. 兜底策略：从头来过

为了避免系统长时间困在错误的局部状态，建议加入显式的兜底策略。它不是“分析失败后的随意重跑”，而是 `SelectiveRegeneration` 输出的一类正式 `RegenMode`。

## 19.1 两级兜底模式

### 模式 A：`fallback_replan_from_l1`

含义：

- 保留当前 case 的 `L1`
- 丢弃当前派生出来的 `L2`
- 丢弃当前派生出来的 `L3`
- 丢弃当前 fragments 和 final query
- 从 `L1 -> L2 -> L3 -> Gen -> Validate` 重新开始

适用场景：

- 怀疑 `L2/L3` 被错误的 pattern bias 带偏
- 多轮局部修补无效，但 `L1` 事实仍基本可信
- step 分解明显不合理，但漏洞事实并未失真

### 模式 B：`fallback_full_replan_from_inputs`

含义：

- 连 `L1` 也不再信任
- 丢弃本轮链路上的 `L1/L2/L3/fragments/query`
- 回到最原始 case 输入重新开始：
  - CVE 描述
  - fix diff
  - repo/context
  - 原始检索入口

适用场景：

- 怀疑最早的事实提取就错了
- failure taxonomy 无法解释当前异常
- 局部修补和软重置都失败
- 系统进入明显的失败震荡状态

## 19.2 兜底触发条件

为了优先保证代码实现简单，建议兜底触发条件先只保留 3 条容易实现的规则，不依赖复杂语义分析。

### 触发器 T1：连续 2 次未知失败

触发条件：

- 连续两轮 `FailureAnalyzer` 输出 `primary_failure_type = unknown_failure`
- 或者连续两轮 `analyzer_confidence` 很低，且无法映射到已有失败规则

动作：

- 触发 `fallback_replan_from_l1`

原因：

- 说明当前失败不适合继续做局部修补
- 但还没有足够证据证明 `L1` 本身错误，因此先做软重置

### 触发器 T2：软重置后再失败

触发条件：

- 上一轮 `regen_mode = fallback_replan_from_l1`
- 本轮验证后仍失败

动作：

- 触发 `fallback_full_replan_from_inputs`

原因：

- 说明问题很可能不只在 `L2/L3/query` 链路
- 连保留下来的 `L1` 也可能已经带偏后续生成

### 触发器 T3：连续 3 次局部修补无改善

触发条件：

- 最近 3 轮都属于局部修补模式，例如：
  - `rerun_composer_only`
  - `rerun_fragments`
  - `rerun_l3` 的局部版本
- 并且最近 3 轮关键指标没有改善，例如：
  - vulnerable 命中数没有增加
  - fixed 命中数没有减少
  - recall 没提升

动作：

- 触发 `fallback_replan_from_l1`

原因：

- 说明系统已经陷入局部最优
- 再继续小修小补的收益很低

### 19.2.1 最小实现思路

这 3 条规则都很适合直接写在 controller 层，不需要复杂模型。

需要维护的最小历史信息：

- 最近几轮 `primary_failure_type`
- 最近几轮 `analyzer_confidence`
- 最近几轮 `regen_mode`
- 最近几轮关键指标

推荐每轮写入 `state_trace.jsonl`，每条记录至少包含：

```json
{
  "iteration": 3,
  "failure_type": "unknown_failure",
  "analyzer_confidence": 0.31,
  "regen_mode": "RERUN_FRAGMENTS",
  "metrics": {
    "vuln_hits": 0,
    "fixed_hits": 0,
    "recall_method": false
  }
}
```

对应的最小伪代码可以写成：

```python
def should_fallback_from_l1(history):
    if last_n_failures_are_unknown(history, n=2):
        return True
    if local_patch_no_improvement(history, n=3):
        return True
    return False


def should_full_reset_from_inputs(history):
    if previous_regen_mode(history) == "FALLBACK_REPLAN_FROM_L1" and current_iteration_failed(history):
        return True
    return False
```

建议第一版就保持这样“笨但稳”的规则，不要一开始加入太多复杂触发器。

## 19.3 兜底策略对应的落盘格式

建议在 `regen_plan.json` 中显式记录兜底模式。

### `fallback_replan_from_l1`

```json
{
  "case_id": "CVE-2025-27818",
  "iteration": 4,
  "rerun_scope": {
    "mode": "fallback_replan_from_l1"
  },
  "reason": "Persistent step decomposition failure without metric improvement",
  "drop_artifacts": [
    "current_l2",
    "current_l3",
    "current_fragments",
    "current_query"
  ],
  "preserve_artifacts": [
    "current_l1",
    "validation_history",
    "state_trace"
  ]
}
```

### `fallback_full_replan_from_inputs`

```json
{
  "case_id": "CVE-2025-27818",
  "iteration": 5,
  "rerun_scope": {
    "mode": "fallback_full_replan_from_inputs"
  },
  "reason": "Unknown failure pattern with repeated low-confidence analysis",
  "drop_artifacts": [
    "current_l1",
    "current_l2",
    "current_l3",
    "current_fragments",
    "current_query"
  ],
  "preserve_artifacts": [
    "validation_history",
    "state_trace"
  ]
}
```

## 19.4 代码实现建议

`SelectiveRegeneration` 最好返回一个统一结构：

```python
{
    "mode": "fallback_replan_from_l1",
    "reason": "...",
    "drop_artifacts": [...],
    "preserve_artifacts": [...],
}
```

控制器据此决定下一跳：

- `fallback_replan_from_l1 -> PLAN_READY`
- `fallback_full_replan_from_inputs -> INIT`

## 19.5 方法意义

兜底策略的重要性在于，它让系统具备以下性质：

- 不会无限困在错误的局部修复链条里
- failure taxonomy 不必覆盖所有现实异常情况
- 方法可以在“层级修复优先”和“全局重置保守兜底”之间平衡

这对论文表述也很重要，因为它说明：

- 你的系统不是脆弱的规则引擎
- 而是一个有保守恢复机制的分层程序综合框架
