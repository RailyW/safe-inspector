# internal/dbclient

`internal/dbclient` 负责 MySQL 的一次性 SQL 执行。

## 包含文件

- `dbclient.go`：实现 MySQL DSN 构造、读查询行收集、写查询影响行数返回、超时和输出截断。

## 安全说明

- 当前只支持 MySQL，配置结构保留 `driver` 字段以便未来扩展其他 SQL。
- 本模块只执行已经通过模板渲染和 `internal/policy` 校验的 SQL。
- MySQL 密码只用于内存中的连接配置，不会写入输出、错误文本或审计日志。
