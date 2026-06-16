# safe-inspector

safe-inspector 是一个使用 Go 编写的纯 CLI 工具，用于给大语言模型提供受控的生产环境访问能力。

它不是 MCP 服务，也不是 HTTP 服务；模型只能通过命令行调用临时执行能力或已批准的 SSH/MySQL 模板。工具的核心目标是：让模型快速获取生产信息，同时让用户可以在“确定性规则、LLM 审批、危险完全放行”三种安全边界之间显式选择。

## 当前能力

- 用户级配置目录：默认使用 `os.UserConfigDir()/safe-inspector`，可通过 `--config-dir` 覆盖。
- 加密认证信息：SSH 密码、SSH key passphrase、sudo 密码、MySQL 密码写入 `secrets.enc`。
- 环境变量解密：执行已批准模板时，CLI 只读取 `SAFE_INSPECTOR_MASTER_KEY` 做内部解密，不要求模型输入秘钥。
- SSH 目标：支持 password 和 key 登录；key 模式保存私钥路径和可选 passphrase，不复制私钥正文。
- MySQL 目标：当前只支持账号密码登录，配置中保留 `driver` 字段以便未来扩展。
- 安全模板：SSH/SQL 模板统一使用 `{{param}}` 参数，并支持 enum、regex、int、bool、identifier、path、string 约束。
- 三种审批模式：默认 `classic`，可切换到 `llm` 或 `danger_allow_all`。
- LLM 审批：`llm` 模式使用 OpenAI Chat Completions structured output 审核每次 SSH/SQL 执行请求；API key 只从配置指定的环境变量读取。
- 危险放行：`danger_allow_all` 模式绕过模板/低风险/LLM 审批，输出和审计会标记 `approval_bypassed=true`。
- 低风险临时执行：目标显式开启 `--allow-adhoc-low-risk` 后，允许观测类 SSH 命令和只读 SQL 单语句直接执行。
- 风险分级：低风险自动执行，中风险返回 `suggested_approval_command` 供用户审批模板，高风险/关键风险直接拒绝。
- SQL 策略：默认只读；INSERT/UPDATE/DELETE 必须使用 `kind=write` 模板；DDL/DCL 和多语句始终拒绝。
- 审计日志：本地 `audit.jsonl` 记录配置变更、风险评估、临时执行、模板新增和执行动作，不记录 secret 或原始命令/SQL 明文。
- 大模型指南：`safe-inspector --skills` 输出给大语言模型阅读的操作说明和审批命令示例。

## 威胁模型

safe-inspector 假设大语言模型可以调用 CLI，但不应持有生产认证信息，也不应自行扩大权限。

因此：

- 默认 `classic` 模式下，执行类命令优先走低风险临时执行；越界动作必须调用已有模板或由用户审批新模板。
- `llm` 模式下，每次 `ssh run`、`ssh exec`、`db query`、`db exec` 都会把不含认证信息的命令/SQL 上下文发送给 LLM reviewer，只有 reviewer 返回 `decision=allow` 才会连接生产资源。
- `danger_allow_all` 模式会跳过所有审批和风险校验，应只在用户明确承担生产风险时短时启用。
- 新增 SSH/DB 目标和新增模板属于策略变更，必须由用户自己在交互式终端执行，并输入主秘钥。
- 模型遇到中风险新需求时，只能展示 CLI 返回的 `suggested_approval_command`，等待用户审核复制执行。
- 模型遇到高风险/关键风险请求时，应停止执行并解释 `risk_reasons`。
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

如果启用 `llm` 审批模式，还需要提供 LLM reviewer 的 API key。默认环境变量名是 `OPENAI_API_KEY`：

```powershell
$env:OPENAI_API_KEY = "sk-..."
```

检查当前状态：

```powershell
.\safe-inspector.exe status
```

默认输出 JSON，例如：

```json
{"approval_mode":"classic","audit_file":true,"config_dir":"...","config_file":true,"env_master_key":true,"ok":true,"secrets_file":true}
```

## 审批模式

safe-inspector 支持三种全局审批模式，旧配置和新初始化配置都默认使用 `classic`：

- `classic`：当前确定性安全边界。低风险临时执行需要目标显式开启 `adhoc_policy`；中风险返回模板审批建议；高风险直接拒绝；模板执行仍按已审批模板执行。
- `llm`：每次 SSH/SQL 执行前调用 OpenAI Chat Completions reviewer。reviewer 只返回固定 JSON 审批结果，不会改写命令或 SQL；API key 从 `OPENAI_API_KEY` 或配置指定的环境变量读取；调用失败时 fail-closed，不执行。
- `danger_allow_all`：危险完全放行模式，跳过 classic 和 LLM 审批，直接执行请求。所有输出和审计都会包含 `approval_bypassed=true`。

查看当前审批模式：

```powershell
.\safe-inspector.exe approval status
```

切回 classic：

```powershell
.\safe-inspector.exe approval mode set --mode classic
```

启用 LLM 审批：

```powershell
.\safe-inspector.exe approval mode set --mode llm --model gpt-5.5 --api-key-env OPENAI_API_KEY
```

测试 LLM reviewer 连通性：

```powershell
.\safe-inspector.exe approval llm test
```

启用危险完全放行必须显式确认：

```powershell
.\safe-inspector.exe approval mode set --mode danger_allow_all --i-understand-production-risk
```

审批模式变更属于策略变更，必须由用户在交互式终端输入主秘钥。LLM API key 不写入 `config.yaml` 或 `secrets.enc`，只通过环境变量读取。

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

显式允许低风险观测命令临时执行：

```powershell
.\safe-inspector.exe ssh add --id prod-web --host 10.0.0.10 --user deploy --auth password --allow-adhoc-low-risk
```

`--allow-adhoc-low-risk` 只允许 `observability-v1` profile 中的低风险命令，例如 `date`、`hostname`、`uptime`、`df`、`free`、`ps`、`ss`、受限的 `systemctl status` 和受限的 `journalctl`。它不允许 `sudo`、服务变更、文件修改、包管理、网络外传或复杂 shell。

## SSH 临时执行

只评估风险、不连接远程机器：

```powershell
.\safe-inspector.exe ssh risk --target prod-web --command "cat /var/log/app.log"
```

在 `classic` 模式下，只有低风险且目标开启 `adhoc_policy` 的命令会执行：

```powershell
.\safe-inspector.exe ssh run --target prod-web --command "systemctl status nginx --no-pager"
```

JSON 输出会包含：

- `decision=allow`：已执行，读取 `stdout`、`stderr`、`exit_code`。
- `decision=template_required`：未执行，复制 `suggested_approval_command` 给用户审批模板。
- `decision=deny`：未执行，读取 `risk_reasons` 解释拒绝原因。

如果目标没有开启 `adhoc_policy`，即使命令是低风险，也会被拒绝；这是为了避免升级后自动扩大生产权限。

在 `llm` 模式下，`ssh run` 会把待执行命令和 classic 风险分级发送给 LLM reviewer；只要 reviewer 返回 `allow` 就会执行，不再要求目标开启 `adhoc_policy`。在 `danger_allow_all` 模式下，命令会直接执行，并标记 `approval_bypassed=true`。

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

显式允许低风险只读 SQL 临时查询：

```powershell
.\safe-inspector.exe db add --id prod-mysql --host 10.0.0.20 --database app --user readonly --allow-adhoc-low-risk
```

`--allow-adhoc-low-risk` 只允许 `readonly-v1` profile 中的单条只读 SQL：`SELECT`、`SHOW`、`DESCRIBE`、`DESC`、`EXPLAIN`。写入 SQL 不会临时执行，会返回模板审批建议。

## MySQL 临时查询

只评估风险、不连接数据库：

```powershell
.\safe-inspector.exe db risk --target prod-mysql --sql "update users set disabled = 1 where id = 42"
```

在 `classic` 模式下，只有低风险只读 SQL 且目标开启 `adhoc_policy` 时会执行：

```powershell
.\safe-inspector.exe db query --target prod-mysql --sql "select count(*) as total from users"
```

JSON 输出会包含 `risk_level`、`risk_reasons`、`decision`、`result`、`audit_id`。当 `decision=template_required` 时，CLI 只返回 `suggested_approval_command`，不会连接数据库。

在 `llm` 模式下，`db query` 会把 SQL 和 classic 风险分级发送给 LLM reviewer；reviewer 返回 `allow` 后会执行原 SQL。`danger_allow_all` 模式会直接执行，写入和 DDL 也会越过 classic 策略；这时 MySQL driver 仍不主动开启多语句。

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
- `INTO OUTFILE`
- `INTO DUMPFILE`
- `LOAD_FILE`
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
- `approval_mode`
- `reviewer`
- `duration_ms`
- `decision`
- `risk_level`
- `risk_reasons`
- `result`
- `error`
- `llm_model`
- `llm_request_id`
- `approval_bypassed`
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
