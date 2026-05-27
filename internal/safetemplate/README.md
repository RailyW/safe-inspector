# internal/safetemplate

`internal/safetemplate` 负责把用户审批过的 SSH/SQL 模板渲染成可执行内容。

## 包含文件

- `renderer.go`：定义参数约束、SSH 命令渲染、SQL prepared statement 渲染。
- `renderer_test.go`：覆盖参数缺失、枚举约束、SQL identifier 安全引用和普通值占位符。

## 安全说明

- 模板参数统一写作 `{{name}}`，执行前必须声明对应 `ParamRule`。
- SSH 参数会被 shell 单引号引用，避免普通参数突破用户审批过的模板结构。
- SQL 中只有 `identifier` 参数会进入 SQL 结构，且必须匹配安全标识符；其他参数统一变成 `?` 占位符和 `Args`。
