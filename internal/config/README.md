# internal/config

`internal/config` 负责 safe-inspector 的用户级配置目录、非敏感策略文件和加密 secret 文件读写。

## 包含文件

- `config.go`：定义 `Config`、`ApprovalConfig`、`LLMApprovalConfig`、`SSHTarget`、`DBTarget`、`AdhocPolicy`、模板结构、secret 结构和 `Store` 读写方法。
- `config_test.go`：覆盖初始化文件布局、配置读取、secret 解密、错误主秘钥拒绝、临时执行策略默认关闭和审批模式默认值。

## 文件职责

- `config.yaml`：保存 SSH/数据库目标、允许模板、参数约束、超时、输出限制、目标级低风险临时执行开关、全局审批模式和 LLM reviewer 非敏感参数。
- `secrets.enc`：保存加密后的 SSH 密码、MySQL 密码、SSH key passphrase、sudo 密码。
- `audit.jsonl`：保存本地审计记录，由 `internal/audit` 追加写入。

## 安全说明

- 本模块不会打印或格式化 secret 明文，只在 `LoadSecrets` 后把内存结构交给执行层使用。
- 默认配置目录来自 `os.UserConfigDir()/safe-inspector`，CLI 可通过 `--config-dir` 覆盖。
- `Init` 不覆盖已有配置文件，避免误删已有生产策略。
- `AdhocPolicy` 的零值必须保持 disabled，旧配置升级后不会自动允许临时执行。
- `ApprovalConfig` 的零值必须归一化为 `classic`，旧配置升级后不会自动启用 LLM 审批或危险放行。
- `LLMApprovalConfig` 只保存 provider、base URL、model、API key 环境变量名、超时和重试次数；API key 本身不写入配置文件。
- LLM 审批始终 fail-closed，归一化配置会强制 `fail_closed=true`。
