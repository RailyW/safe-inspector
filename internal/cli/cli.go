// Package cli 实现 safe-inspector 的命令行入口。
//
// CLI 是本项目唯一公开接口：大语言模型通过 --help 和 --skills 学习能力，
// 再通过一次性命令调用已审批的 SSH/SQL 模板。
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/secure"
	"golang.org/x/term"
)

const defaultFormat = "json"

type globalOptions struct {
	ConfigDir string
	Format    string
	Help      bool
	Skills    bool
}

// Run 执行 CLI 命令并返回进程退出码。
// stdin/stdout/stderr 作为参数传入，便于测试；隐藏输入仍会直接读取当前 TTY。
func Run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	opts, rest, err := parseGlobalOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if opts.Skills {
		fmt.Fprint(stdout, SkillsText())
		return 0
	}
	if opts.Help || len(rest) == 0 {
		fmt.Fprint(stdout, HelpText())
		return 0
	}

	store, err := config.NewStore(opts.ConfigDir)
	if err != nil {
		return writeError(stderr, err)
	}

	switch rest[0] {
	case "init":
		return runInit(store, opts, stdout, stderr)
	case "status":
		return runStatus(store, opts, stdout, stderr)
	case "ssh":
		return runSSH(store, opts, rest[1:], stdout, stderr)
	case "db":
		return runDB(store, opts, rest[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知命令: %s\n\n%s", rest[0], HelpText())
		return 2
	}
}

func parseGlobalOptions(args []string) (globalOptions, []string, error) {
	opts := globalOptions{Format: defaultFormat}
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--help", "-h":
			opts.Help = true
		case "--skills":
			opts.Skills = true
		case "--config-dir":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("--config-dir 缺少值")
			}
			opts.ConfigDir = args[i]
		case "--format":
			i++
			if i >= len(args) {
				return opts, nil, fmt.Errorf("--format 缺少值")
			}
			opts.Format = args[i]
		default:
			rest = append(rest, args[i:]...)
			return opts, rest, validateFormat(opts.Format)
		}
	}
	return opts, rest, validateFormat(opts.Format)
}

func validateFormat(format string) error {
	if format != "json" && format != "text" {
		return fmt.Errorf("未知输出格式 %q，只支持 json 或 text", format)
	}
	return nil
}

func runInit(store config.Store, opts globalOptions, stdout io.Writer, stderr io.Writer) int {
	masterKey, err := promptMasterKey(stdout, "请输入 safe-inspector 主秘钥: ")
	if err != nil {
		return writeError(stderr, err)
	}
	if err := store.Init(masterKey); err != nil {
		return writeError(stderr, err)
	}
	result := map[string]any{
		"ok":           true,
		"config_dir":   store.Paths.Dir,
		"config_file":  store.Paths.ConfigFile,
		"secrets_file": store.Paths.SecretsFile,
		"audit_file":   store.Paths.AuditFile,
	}
	return writeValue(stdout, opts.Format, result)
}

func runStatus(store config.Store, opts globalOptions, stdout io.Writer, stderr io.Writer) int {
	status := map[string]any{
		"ok":             true,
		"config_dir":     store.Paths.Dir,
		"config_file":    fileExists(store.Paths.ConfigFile),
		"secrets_file":   fileExists(store.Paths.SecretsFile),
		"audit_file":     fileExists(store.Paths.AuditFile),
		"env_master_key": os.Getenv(secure.EnvMasterKey) != "",
	}
	return writeValue(stdout, opts.Format, status)
}

func writeValue(stdout io.Writer, format string, value any) int {
	if format == "text" {
		renderText(stdout, value)
		return 0
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return 1
	}
	return 0
}

func renderText(stdout io.Writer, value any) {
	switch v := value.(type) {
	case string:
		fmt.Fprintln(stdout, v)
	case map[string]any:
		for key, item := range v {
			fmt.Fprintf(stdout, "%s: %v\n", key, item)
		}
	default:
		data, _ := json.MarshalIndent(value, "", "  ")
		fmt.Fprintln(stdout, string(data))
	}
}

func writeError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func promptMasterKey(stdout io.Writer, prompt string) (string, error) {
	return promptHiddenRequired(stdout, prompt, "主秘钥")
}

func promptHiddenRequired(stdout io.Writer, prompt string, fieldName string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("该命令必须由用户在交互式终端中输入%s", fieldName)
	}
	fmt.Fprint(stdout, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stdout)
	if err != nil {
		return "", fmt.Errorf("读取%s失败: %w", fieldName, err)
	}
	if strings.TrimSpace(string(value)) == "" {
		return "", fmt.Errorf("%s不能为空", fieldName)
	}
	return string(value), nil
}

func HelpText() string {
	return `safe-inspector - 面向大语言模型的生产环境安全 CLI 工具层

用法:
  safe-inspector [--config-dir DIR] [--format json|text] <command>
  safe-inspector --skills

全局命令:
  init                         初始化用户级配置和加密 secret 文件
  status                       检查配置文件、secret 文件和环境变量状态
  ssh add                      添加 SSH 目标
  ssh template add             为 SSH 目标添加安全命令模板
  ssh exec                     执行已批准的 SSH 命令模板
  db add                       添加 MySQL 目标
  db template add              为 MySQL 目标添加安全 SQL 模板
  db exec                      执行已批准的 SQL 模板

关键约束:
  - 默认输出 JSON，可用 --format text 切换人工可读输出。
  - 执行命令只读取 SAFE_INSPECTOR_MASTER_KEY 做内部解密，不输出认证信息。
  - 新增目标和模板必须在交互式终端输入主秘钥。
  - SSH 不做额外危险命令拦截，安全边界来自用户审批过的模板。
  - MySQL 默认只读，写入必须使用 kind=write 模板，DDL/DCL 和多语句始终拒绝。
`
}

func SkillsText() string {
	return `# safe-inspector CLI skills

你是大语言模型时，应把 safe-inspector 当成只读优先、模板受控的生产环境访问工具。

## 基本原则

- 不要输出密码、SSH 私钥 passphrase、sudo 密码、MySQL 密码或主秘钥。
- 不要尝试绕过安全模板；只能执行已经存在的模板。
- 如果用户请求的新 SSH 命令或 SQL 没有模板，你只能生成待用户复制执行的审批命令，不能自行执行审批。
- 执行命令默认返回 JSON，优先解析 ` + "`ok`" + `、` + "`error`" + `、` + "`stdout`" + `、` + "`result`" + `、` + "`audit_id`" + ` 字段。

## 查看状态

` + "```powershell" + `
safe-inspector status
` + "```" + `

## 执行已批准 SSH 模板

` + "```powershell" + `
safe-inspector ssh exec --target prod-web --template service-status --param service=nginx
` + "```" + `

## 执行已批准 MySQL 模板

` + "```powershell" + `
safe-inspector db exec --target prod-mysql --template find-user --param id=42
` + "```" + `

## 生成 SSH 模板审批命令

当缺少模板时，输出给用户审核并手动执行：

` + "```powershell" + `
safe-inspector ssh template add --target prod-web --name service-status --command "systemctl status {{service}}" --param service:enum=nginx,mysql
` + "```" + `

## 生成 SQL 模板审批命令

只读查询示例：

` + "```powershell" + `
safe-inspector db template add --target prod-mysql --name find-user --kind read --sql "select * from {{table}} where id = {{id}}" --param table:identifier --param id:int
` + "```" + `

写入 SQL 必须显式 ` + "`--kind write`" + `，并且仍会拒绝 DROP/ALTER/TRUNCATE/CREATE/GRANT/REVOKE 等 DDL/DCL。

## 参数规则

- ` + "`name:enum=a,b`" + `：只允许枚举值。
- ` + "`name:regex=^[a-z]+$`" + `：只允许匹配正则。
- ` + "`name:int`" + `：整数。
- ` + "`name:bool`" + `：布尔值。
- ` + "`name:identifier`" + `：SQL 标识符。
- ` + "`name:path`" + `：路径参数。
- ` + "`name:string`" + `：普通字符串。
`
}
