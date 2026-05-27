# cmd/safe-inspector

`cmd/safe-inspector` 是 safe-inspector 的 Go 程序入口。

## 包含文件

- `main.go`：读取命令行参数和标准输入输出，把执行交给 `internal/cli.Run`，并使用返回值作为进程退出码。

## 安全说明

- 入口层不解析 secret，不读取配置文件，也不实现业务逻辑。
- 所有认证信息、模板校验、SSH/MySQL 执行都在 `internal` 包中完成，便于集中审计。
