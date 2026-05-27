# internal/cli

`internal/cli` 是 safe-inspector 的命令行接口层，也是大语言模型实际调用的唯一入口。

## 包含文件

- `cli.go`：全局参数解析、`init`、`status`、`--help`、`--skills` 输出。
- `commands.go`：管理类主秘钥校验、执行类环境变量解密、审计写入等共享命令辅助函数。
- `params.go`：解析 `--param key=value` 和模板审批参数规则。
- `ssh.go`：SSH 目标管理、SSH 模板审批、SSH 模板执行。
- `db.go`：MySQL 目标管理、SQL 模板审批、SQL 模板执行。
- `cli_test.go`：覆盖 `--skills` 和 `status` 的稳定输出。

## 安全说明

- CLI 默认输出 JSON，避免大模型从自由文本里猜测执行状态。
- 管理类命令必须在交互式终端输入主秘钥；执行类命令只读取 `SAFE_INSPECTOR_MASTER_KEY` 环境变量。
- `--skills` 是给大模型阅读的操作指南，明确禁止模型自行审批模板或输出认证信息。
