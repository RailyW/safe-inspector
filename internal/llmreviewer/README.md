# internal/llmreviewer

`internal/llmreviewer` 负责把 safe-inspector 的审批请求发送到 OpenAI Chat Completions，并解析模型返回的结构化审批结果。

## 包含文件

- `llmreviewer.go`：实现 Chat Completions HTTP 客户端、JSON Schema response format、审批请求构造、响应解析、错误处理和配置默认值补齐。
- `llmreviewer_test.go`：覆盖 structured output 请求、allow 响应解析、API key 缺失 fail-closed 和 base URL endpoint 拼接。

## 文件职责

- `Client`：保存非敏感 LLM 配置和 HTTP client。
- `Review`：读取配置指定的 API key 环境变量，构造 Chat Completions 请求，解析固定 JSON 审批结果。
- `approvalSchema`：定义 reviewer 必须返回的 JSON Schema，字段包括 `decision`、`risk_level`、`reason`、`policy_violations` 和 `confidence`。
- `parseChatResponse`：处理 Chat Completions 响应、模型拒答和结构化内容解析。

## 安全说明

- API key 只从环境变量读取，不写入配置文件、审计日志或 CLI 输出。
- 发送给 LLM 的请求只包含 `approval.Request`，不得加入任何 AUTH 信息。
- reviewer 只能批准或拒绝，不允许修改 SSH 命令或 SQL；CLI 会执行原始文本。
- HTTP 错误、模型拒答、空 choices、非 JSON 内容、未知 decision/risk_level 都会返回错误，由 CLI fail-closed 拒绝执行。
- 默认 base URL 是 `https://api.openai.com/v1`；实现同时兼容带 `/v1` 和不带 `/v1` 的自定义 base URL。
