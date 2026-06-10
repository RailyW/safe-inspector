# internal/risk

`internal/risk` 负责 safe-inspector 的低风险临时执行分级。它只根据 SSH 命令文本或 SQL 文本做确定性判断，不读取配置 secret、不连接 SSH、不连接数据库。

## 包含文件

- `risk.go`：定义风险等级、执行决策、评估结果结构，以及 SSH/SQL 风险分类器。
- `risk_test.go`：覆盖只读 SQL、DML、DDL/DCL、文件函数、多语句、SSH 观测命令、sudo、复杂 shell 和破坏性命令。

## 主要接口

- `ClassifySQL(query string) Assessment`：把 SQL 分为 low/medium/high/critical，并返回 allow/template_required/deny。
- `ClassifySSHCommand(command string) Assessment`：把 SSH 命令分为低风险观测命令、中风险模板审批、或高风险拒绝。
- `Allows(maxRisk string, level Level) bool`：判断目标级 `adhoc_policy.max_risk` 是否允许某个风险等级。

## 安全说明

- SQL 第一版只允许单条只读语句临时执行；写入语句返回模板审批建议；DDL/DCL、多语句、文件函数、延迟函数和权限相关语句拒绝。
- SSH 第一版只允许 `observability-v1` 中的观测类命令临时执行；未知命令、sudo、复杂 shell 返回模板审批建议；破坏性、持久化变更、服务变更和网络外传命令拒绝。
- 本模块的判断结果只是执行前置条件；CLI 仍必须检查目标级 `adhoc_policy` 是否显式开启。
