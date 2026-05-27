# internal/sshclient

`internal/sshclient` 负责连接 SSH 目标并执行一次性命令。

## 包含文件

- `sshclient.go`：实现 password/key 登录、可选 sudo 执行、超时控制和输出截断。

## 安全说明

- 本模块不判断命令是否安全，只执行上层已经通过模板渲染和策略校验的命令。
- SSH key 模式只读取配置中的私钥路径，不把私钥正文导入 safe-inspector 配置。
- 如果本机存在 `~/.ssh/known_hosts`，会使用 known_hosts 校验；否则第一版回退到 `InsecureIgnoreHostKey`，生产环境建议先维护 known_hosts。
- sudo 只有调用方传入 `useSudo=true` 时才使用，sudo 密码通过 stdin 写入，不出现在命令字符串和输出中。
