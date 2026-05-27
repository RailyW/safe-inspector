# internal/audit

`internal/audit` 负责 safe-inspector 的本地 JSONL 审计日志。

## 包含文件

- `audit.go`：定义审计事件结构、随机审计 ID 和追加写入器。

## 审计内容

审计记录包含动作、目标、模板、参数摘要、执行状态、耗时和错误类别。审计日志用于追踪“大模型调用了什么已批准能力”，而不是保存执行明文上下文。

## 安全说明

- 不记录主秘钥、SSH 密码、MySQL 密码、私钥 passphrase、sudo 密码。
- 参数只记录调用方传入的非 secret 模板参数；后续如果引入 secret 类型参数，必须在写入前脱敏。
