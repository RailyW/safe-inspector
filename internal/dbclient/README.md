# internal/dbclient

`internal/dbclient` 负责 MySQL 的一次性 SQL 执行。

## 包含文件

- `dbclient.go`：实现 MySQL DSN 构造、classic 校验执行入口、LLM/danger 已审批执行入口、读查询行收集、写查询影响行数返回、超时和输出截断。

## 安全说明

- 当前只支持 MySQL，配置结构保留 `driver` 字段以便未来扩展其他 SQL。
- `Execute` 用于 classic 模式，会调用 `internal/policy` 校验 SQL 读写类型、DDL/DCL 和多语句边界。
- `ExecuteApproved` 用于 LLM/danger 模式，假设调用方已经完成审批，不再重复 classic SQL 风险校验；调用方必须传入 `read` 或 `write` 决定使用 Query 还是 Exec。
- MySQL 密码只用于内存中的连接配置，不会写入输出、错误文本或审计日志。
- 本模块不主动开启 MySQL 多语句能力；即使 danger 模式绕过上层策略，也不会额外改变 driver 默认安全选项。
