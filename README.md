# safe-inspector

safe-inspector 是一个使用 Go 编写的纯 CLI 工具，用于给大语言模型提供受控的生产环境访问能力。

它不是 MCP 服务，也不是 HTTP 服务；模型只能通过命令行调用已批准的 SSH 或 MySQL 模板。工具的核心目标是：让模型快速获取生产信息，同时把 SSH 命令和 SQL 执行限制在用户明确审批过的安全模板内。

## 当前能力

- 用户级配置目录：默认使用 `os.UserConfigDir()/safe-inspector`，可通过 `--config-dir` 覆盖。
- 加密认证信息：SSH 密码、SSH key passphrase、sudo 密码、MySQL 密码写入 `secrets.enc`。
- 环境变量解密：执行已批准模板时，CLI 只读取 `SAFE_INSPECTOR_MASTER_KEY` 做内部解密，不要求模型输入秘钥。
- SSH 目标：支持 password 和 key 登录；key 模式保存私钥路径和可选 passphrase，不复制私钥正文。
- MySQL 目标：当前只支持账号密码登录，配置中保留 `driver` 字段以便未来扩展。
- 安全模板：SSH/SQL 模板统一使用 `{{param}}` 参数，并支持 enum、regex、int、bool、identifier、path、string 约束。
- SQL 策略：默认只读；INSERT/UPDATE/DELETE 必须使用 `kind=write` 模板；DDL/DCL 和多语句始终拒绝。
- 审计日志：本地 `audit.jsonl` 记录配置变更、模板新增和执行动作，不记录 secret。
- 大模型指南：`safe-inspector --skills` 输出给大语言模型阅读的操作说明和审批命令示例。

## 威胁模型

safe-inspector 假设大语言模型可以调用 CLI，但不应持有生产认证信息，也不应自行扩大权限。

因此：

- 执行类命令只允许调用已有模板。
- 新增 SSH/DB 目标和新增模板属于策略变更，必须由用户自己在交互式终端执行，并输入主秘钥。
- 模型遇到新需求时，只能生成待用户审核复制的 `ssh template add` 或 `db template add` 命令。
- 所有输出默认脱敏，不打印 SSH 密码、MySQL 密码、sudo 密码、私钥 passphrase 或主秘钥。

## 安装与构建

```powershell
go build -o safe-inspector.exe .\cmd\safe-inspector
```

查看帮助：

```powershell
.\safe-inspector.exe --help
```

查看大语言模型使用指南：

```powershell
.\safe-inspector.exe --skills
```

## 初始化

初始化配置目录时，需要用户在交互式终端输入主秘钥：

```powershell
.\safe-inspector.exe init
```

执行已批准模板前，把同一个主秘钥放入环境变量：

```powershell
$env:SAFE_INSPECTOR_MASTER_KEY = "your-master-key"
```

检查当前状态：

```powershell
.\safe-inspector.exe status
```

默认输出 JSON，例如：

```json
{"audit_file":true,"config_dir":"...","config_file":true,"env_master_key":true,"ok":true,"secrets_file":true}
```

## 添加 SSH 目标

密码登录：

```powershell
.\safe-inspector.exe ssh add --id prod-web --host 10.0.0.10 --user deploy --auth password
```

私钥登录：

```powershell
.\safe-inspector.exe ssh add --id prod-web --host 10.0.0.10 --user deploy --auth key --key-path C:\Users\me\.ssh\id_rsa
```

私钥有 passphrase 时：

```powershell
.\safe-inspector.exe ssh add --id prod-web --host 10.0.0.10 --user deploy --auth key --key-path C:\Users\me\.ssh\id_rsa --with-key-passphrase
```

允许 sudo 模板：

```powershell
.\safe-inspector.exe ssh add --id prod-web --host 10.0.0.10 --user deploy --auth password --allow-sudo
```

`--allow-sudo` 只表示该目标可以配置 sudo 模板；具体模板仍需添加 `--sudo` 才会提权。

## 添加 SSH 安全模板

简单命令参数：

```powershell
.\safe-inspector.exe ssh template add --target prod-web --name service-status --command "systemctl status {{service}}" --param service:enum=nginx,mysql
```

sudo 模板：

```powershell
.\safe-inspector.exe ssh template add --target prod-web --name restart-nginx --sudo --command "systemctl restart {{service}}" --param service:enum=nginx
```

使用 JSON 文件导入复杂模板：

```json
{
  "name": "journal-tail",
  "target": "prod-web",
  "command": "journalctl -u {{service}} -n {{lines}} --no-pager",
  "params": {
    "service": {"type": "enum", "enum": ["nginx", "mysql"]},
    "lines": {"type": "int"}
  },
  "sudo": false,
  "timeout_seconds": 30,
  "max_output_bytes": 1048576,
  "description": "查看指定服务最近日志"
}
```

```powershell
.\safe-inspector.exe ssh template add --from-file .\journal-tail.json
```

## 执行 SSH 模板

```powershell
.\safe-inspector.exe ssh exec --target prod-web --template service-status --param service=nginx
```

SSH 参数会在渲染时进行 shell 单引号引用。SSH 命令层完全信任用户已审批模板，不额外拦截危险命令，因此请谨慎审批模板。

## 添加 MySQL 目标

```powershell
.\safe-inspector.exe db add --id prod-mysql --host 10.0.0.20 --port 3306 --database app --user readonly
```

当前只支持 MySQL：

```powershell
.\safe-inspector.exe db add --id prod-mysql --driver mysql --host 10.0.0.20 --database app --user readonly
```

## 添加 SQL 安全模板

只读查询：

```powershell
.\safe-inspector.exe db template add --target prod-mysql --name find-user --kind read --sql "select * from {{table}} where id = {{id}}" --param table:identifier --param id:int
```

显式写入：

```powershell
.\safe-inspector.exe db template add --target prod-mysql --name disable-user --kind write --sql "update users set disabled = {{disabled}} where id = {{id}}" --param disabled:bool --param id:int
```

SQL 模板中，`identifier` 参数会被反引号引用；其他参数会转换成 prepared statement 的 `?` 占位符。

第一版始终拒绝：

- 多语句 SQL。
- `DROP`
- `ALTER`
- `TRUNCATE`
- `CREATE`
- `GRANT`
- `REVOKE`

## 执行 SQL 模板

```powershell
.\safe-inspector.exe db exec --target prod-mysql --template find-user --param table=users --param id=42
```

默认 JSON 输出包含：

- `ok`
- `target`
- `template`
- `duration_ms`
- `result`
- `error`
- `audit_id`

## 参数规则

- `name:enum=a,b`：只允许枚举值。
- `name:regex=^[a-z]+$`：只允许匹配正则。
- `name:int`：整数。
- `name:bool`：布尔值。
- `name:identifier`：SQL 标识符。
- `name:path`：路径参数。
- `name:string`：普通字符串。

## 本地文件

默认配置目录包含：

- `config.yaml`：非敏感策略文件。
- `secrets.enc`：加密 secret 文件。
- `audit.jsonl`：审计日志。

可以用 `--config-dir` 指定其他目录：

```powershell
.\safe-inspector.exe --config-dir D:\safe-inspector-config status
```

## 开发

运行定向测试：

```powershell
go test .\internal\...
```

构建 CLI：

```powershell
go build .\cmd\safe-inspector
```
