# 面向 CVE 到 CodeQL 合成的形式化四层中间表示

## 摘要

本文定义了一种四层中间表示（IR），用于基于 CVE 描述、补丁证据和代码级制品自动合成 CodeQL 查询。其核心动机在于：许多漏洞类别无法被单一的 source-sink-sanitizer 抽象准确刻画。因此，我们将案例事实、语义结构、查询构造步骤以及后端降级过程划分为彼此独立的层。进一步地，我们引入了带类型的 Schema IR，并为不同漏洞类别定义子类型，从而更精确地建模污点流漏洞、缺失校验缺陷、不完整安全策略、不安全默认值、鉴权绕过以及状态或生命周期违规等问题。

## 1. 引言

自动化的漏洞到查询生成需要一种同时满足以下要求的中间表示：

- 具有足够表达力，以覆盖多样化的漏洞类别
- 具有足够结构化程度，以支持程序化地降级为静态分析查询
- 具有足够模块化，以避免将案例证据、语义抽象和后端特定实现细节混杂在一起

现有的 source-sink-sanitizer 抽象对污点类漏洞效果较好，但对不完整策略执行、不安全默认值或授权绑定失败等类别并不充分。为解决这一局限，我们定义了一种分层 IR 架构与带类型的语义模式。

## 2. 四层架构

令一个案例的整体表示为：

```text
IR = (L1, L2, L3, L4)
```

其中：

- `L1` 为漏洞事实层
- `L2` 为语义 Schema IR 层
- `L3` 为查询构造步骤层
- `L4` 为后端降级 IR 层

我们施加严格的依赖顺序：

```text
L1 -> L2 -> L3 -> L4
```

即，每一层只能依赖其前序层的信息。

### 2.1 层语义

令：

- `F` 表示可观测事实
- `S` 表示语义对象与关系
- `P` 表示查询构造步骤集合
- `B` 表示后端降级规范

则：

- `L1 = F`
- `L2 = phi(F) = S`
- `L3 = psi(S) = P`
- `L4 = omega(P) = B`

其中，`phi`、`psi` 和 `omega` 是转换函数。

## 3. 漏洞事实层

我们将事实层定义为：

```text
L1 = (M, C, D, E)
```

其中：

- `M` 是元数据
- `C` 是代码事实集合
- `D` 是补丁事实集合
- `E` 是环境事实集合

一个事实表示为元组：

```text
f = (id, kind, subject, proposition, evidence)
```

其性质如下：

1. `L1` 是描述性的，而非推理性的。
2. `L1` 不包含后端特定实现构造。
3. `L1` 不预设固定漏洞模式。

## 4. 语义 Schema IR

我们将语义层定义为：

```text
L2 = (T, Ent, Rel, Con, G, Env, Ev, Rep)
```

其中：

- `T` 是漏洞模式类型
- `Ent` 是有限实体集合
- `Rel` 是有限关系集合
- `Con` 是有限漏洞约束集合
- `G` 是有限保护条件（guard）集合
- `Env` 是有限环境条件集合
- `Ev` 是有限证据链接集合
- `Rep` 是报告规范

### 4.1 实体

实体表示为元组：

```text
e = (id, kind, attrs)
```

其中，`kind` 取值来自受控词表，例如：

```text
input, subject, policy, policy_member, check, action,
config_key, config_value, constant, api_call, api_result,
container, transform, sanitizer, guard_value
```

### 4.2 关系

关系表示为元组：

```text
r = (id, type, src, dst, attrs)
```

其中，`src` 和 `dst` 引用实体标识符。

典型关系类型包括：

```text
reads_from, derived_from, flows_to, checks, protects, uses_policy,
contains_member, missing_member, compares_against, controls,
blocks, allows, normalizes, validates, aliases
```

### 4.3 约束与保护条件

约束（constraint）表达一种其满足会促成漏洞状态的条件。

```text
c = (id, kind, target, params)
```

保护条件（guard）表达一种在非漏洞状态下应当成立的条件。

```text
g = (id, kind, target, params)
```

直观上：

- constraints 用于刻画漏洞特征
- guards 用于刻画期望防护

## 5. 带类型的 Schema IR

语义层由模式类型 `T` 参数化。

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

每个 `T` 诱导一个包含必需语义槽位的模式子类型。

### 5.1 污点流

当 `T = taint_flow` 时，最小模式为：

```text
L2_taint = (Sources, Sinks, Propagators, Sanitizers, FlowConstraints)
```

正确性条件：

```text
exists s in Sources, k in Sinks :
  reachable(s, k) and not blocked_by_sanitizer(s, k)
```

### 5.2 缺失校验

当 `T = missing_validation` 时，最小模式为：

```text
L2_mv = (Subject, DangerousAction, ExpectedValidation, MissingGuard)
```

正确性条件：

```text
uses(DangerousAction, Subject) and not validated_by(Subject, ExpectedValidation)
```

### 5.3 不完整安全策略

当 `T = incomplete_security_policy` 时，最小模式为：

```text
L2_isp = (Policy, PolicyKind, Subject, PolicyCheck, RequiredMemberOrRule, ViolationConstraint)
```

正确性条件：

```text
uses_policy(PolicyCheck, Policy) and
checks(PolicyCheck, Subject) and
missing(Policy, RequiredMemberOrRule)
```

该模式特别适用于如下场景：安全检查在语法层面存在，但其执行的策略在语义层面并不完整。

### 5.4 不安全默认值

当 `T = unsafe_default` 时，最小模式为：

```text
L2_ud = (DefaultValue, ControlledFeature, SafeExpectedValue, UnsafeCondition)
```

### 5.5 鉴权绕过

当 `T = authorization_bypass` 时，最小模式为：

```text
L2_ab = (Principal, ProtectedResource, AuthorizationCheck, IncorrectBinding)
```

### 5.6 状态或生命周期违规

当 `T = state_or_lifecycle_violation` 时，最小模式为：

```text
L2_slv = (Resource, StateTransition, UnsafeAction, StateConstraint)
```

## 6. 查询构造步骤层

我们将查询构造步骤层定义为：

```text
L3 = (Goal, Steps)
```

其中：

- `Goal` 是构造目标
- `Steps` 是有限语义单元步骤集合

每个步骤表示为元组：

```text
step = (id, u, d, R, In, Out, t, H, Exp)
```

其中：

- `u` 是语义单元类型
- `d` 是自然语言描述
- `R` 是指向 `L2` 的引用集合
- `In` 是所需符号集
- `Out` 是产出符号集
- `t` 是代码片段类型
- `H` 是检索提示集合
- `Exp` 是期望输出约定

与符号化执行计划不同，`L3` 不要求构成 DAG。它的目标不是编码一个可完全执行的证明策略，而是将 `L2` 拆解为一组可检索、可翻译、可组合的语义单元。一个步骤若能被稳定翻译为以下少数几类代码片段之一，则可认为其是良构的：

```text
helper_predicate, relation_predicate, constraint_fragment,
where_clause, select_clause, query_skeleton
```

这带来三个重要性质：

1. 每个 step 都可作为 CodeQL 知识检索查询。
2. 每个 step 都可被翻译为独立的查询片段。
3. 整个层次在语义上保持后端无关。

## 7. 后端降级 IR

我们将后端降级层定义为：

```text
L4 = (Backend, QueryKind, Imports, Map, PredTmpl, SelectTmpl)
```

其中：

- `Backend` 标识目标分析后端
- `QueryKind` 标识查询族，例如 `problem` 或 `path-problem`
- `Imports` 是所需库集合
- `Map` 将语义关系与约束映射为后端谓词
- `PredTmpl` 是谓词模板集合
- `SelectTmpl` 定义报告行为

对于 CodeQL：

- 语义实体通常降级为绑定谓词
- `flows_to` 通常降级为 `DataFlow` 或 `TaintTracking`
- `uses_policy` 等结构关系通常降级为连接谓词
- `missing_member` 等约束通常降级为值谓词或集合谓词

## 8. 可选污点视图

我们明确将面向污点的构造视为一种“视图”，而非通用本体。

令：

```text
TV = (Sources, Sinks, Sanitizers)
```

则：

- 若 `T = taint_flow`，则 `TV` 是必需的
- 否则，`TV` 是可选的

这可避免在非污点场景下产生语义扭曲。

## 9. 示例：CVE-2025-27818

我们将 `CVE-2025-27818` 归类为：

```text
T = incomplete_security_policy
```

因为该漏洞源于不完整的拒绝名单（denylist），而非经典污点流问题。

令：

- `P` 表示默认的禁止登录模块策略
- `S` 表示登录模块名称
- `C` 表示成员检查逻辑
- `R` 表示必须被阻止的模块 `LdapLoginModule`

则漏洞条件为：

```text
uses_policy(C, P) and checks(C, S) and missing(P, R)
```

相应的查询构造步骤可表示为：

1. 定位策略制品 `P`
2. 定位策略检查点 `C`
3. 构造连接 `C` 与 `P` 的片段
4. 构造约束 `missing(P, R)` 的片段
5. 构造锚定于 `P` 的报告片段

这些步骤的目标是驱动检索与片段生成，而不是编码一个严格的证明 DAG。除非需要额外的来源追踪证据，否则它们并不要求采用 path-problem 编码。

## 10. 设计不变量

我们要求以下不变量：

1. `L1` 包含事实，而非后端逻辑。
2. `L2` 包含语义，而非可执行查询代码。
3. `L3` 包含语义单元构造步骤，而非后端语法。
4. `L4` 包含降级策略，而非新增漏洞语义。
5. `L2` 中每个推导出的语义对象都应可追溯到 `L1` 中的证据。

## 11. 结论

本文提出的四层 IR 将证据、语义、查询构造与后端实现清晰分离。其关键创新在于带类型的 Schema IR 与基于语义单元的 `L3`：它们避免将所有漏洞过度拟合为污点风格抽象，或过早拟合为编译器式证明计划。这使得对不完整策略执行、不安全默认值和授权失败等非污点漏洞的建模更加忠实，同时在适用场景下仍可支持经典 source-sink-sanitizer 建模。
