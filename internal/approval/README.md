# internal/approval

`internal/approval` 定义 safe-inspector 的执行审批抽象，负责把 classic、LLM 和危险放行模式统一成同一套请求/结果结构。

## 包含文件

- `approval.go`：定义 `Request`、`Result`、`Approver` 接口、`ClassicApprover`、`DangerApprover` 和 fail-closed 结果构造函数。
- `approval_test.go`：覆盖危险放行模式必须返回 `allow` 且标记 `approval_bypassed=true`。

## 文件职责

- `Request`：描述一次待执行动作，包括操作类型、目标、模板名、SSH 命令、SQL、SQL kind、sudo 标记、非敏感参数和 classic 风险分级。
- `Result`：描述审批结果，包括 `approval_mode`、`reviewer`、`decision`、`risk_level`、原因、LLM 元数据和危险放行标记。
- `Approver`：所有审批器的共同接口，CLI 只依赖该接口决定是否继续连接生产资源。
- `ClassicApprover`：保留现有确定性策略结果；模板执行由 CLI 预先校验后以 allow 进入。
- `DangerApprover`：完全放行审批器，始终返回 allow，并把 `approval_bypassed` 标记为 true。

## 安全说明

- `Request` 严禁包含 SSH 密码、MySQL 密码、sudo 密码、私钥 passphrase 或主秘钥。
- 审批器只能返回 allow/deny 等决策，不能改写命令或 SQL；执行层必须执行原始请求文本。
- 危险放行模式的结果必须保留 `approval_bypassed=true`，供 CLI 输出和审计日志共同标记。
- LLM reviewer 出错时由 CLI 使用 `DeniedResult` 生成 fail-closed 的拒绝结果。
