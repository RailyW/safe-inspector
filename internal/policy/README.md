# internal/policy

`internal/policy` 负责渲染之后、真正执行之前的策略校验。

## 包含文件

- `policy.go`：实现 SQL 读写类型校验、DDL/DCL 拒绝、多语句拒绝、sudo 使用边界校验。
- `policy_test.go`：覆盖只读 SQL、显式写入 SQL、危险 SQL 拒绝、sudo 目标权限校验。

## 安全说明

- SSH 命令完全信任已经由用户审批过的模板，不在本包内做额外危险命令拦截。
- MySQL 第一版保留硬边界：默认只读，写入必须 `kind=write`，DDL/DCL 和多语句始终拒绝。
- sudo 需要目标机器和模板两边同时声明，避免“目标允许 sudo”被误解为所有模板自动提权。
