# internal/cli

`internal/cli` 是 safe-inspector 的命令行接口层，也是大语言模型实际调用的唯一入口。

## 包含文件

- `cli.go`：全局参数解析、`init`、`status`、`--help`、`--skills` 输出。
- `adhoc.go`：低风险临时执行的共享响应字段、审批建议命令、审计摘要辅助函数。
- `commands.go`：管理类主秘钥校验、执行类环境变量解密、审计写入等共享命令辅助函数。
- `params.go`：解析 `--param key=value` 和模板审批参数规则。
- `ssh.go`：SSH 目标管理、SSH 模板审批、SSH 模板执行、SSH 风险评估和低风险临时执行。
- `db.go`：MySQL 目标管理、SQL 模板审批、SQL 模板执行、SQL 风险评估和低风险临时查询。
- `cli_test.go`：覆盖 `--skills`、`status`、临时执行开关、风险建议和执行器注入。

## 安全说明

- CLI 默认输出 JSON，避免大模型从自由文本里猜测执行状态。
- 管理类命令必须在交互式终端输入主秘钥；执行类命令只读取 `SAFE_INSPECTOR_MASTER_KEY` 环境变量。
- `ssh run` 和 `db query` 只有在目标显式开启 `adhoc_policy` 且风险分级为 low/allow 时才会读取 secret 并连接远程资源。
- 中风险临时动作只输出 `suggested_approval_command`，不连接生产资源；高风险动作直接返回 `decision=deny`。
- `--skills` 是给大模型阅读的操作指南，明确要求模型优先尝试低风险临时执行，遇到模板审批建议时等待用户手动审批，禁止模型输出认证信息。
