package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RailyW/safe-inspector/internal/audit"
	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/dbclient"
	"github.com/RailyW/safe-inspector/internal/policy"
	"github.com/RailyW/safe-inspector/internal/safetemplate"
)

func runDB(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "db 缺少子命令：add、template add、exec")
		return 2
	}
	switch args[0] {
	case "add":
		return runDBAdd(store, opts, args[1:], stdout, stderr)
	case "template":
		if len(args) >= 2 && args[1] == "add" {
			return runDBTemplateAdd(store, opts, args[2:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "db template 仅支持 add")
		return 2
	case "exec":
		return runDBExec(store, opts, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知 db 子命令: %s\n", args[0])
		return 2
	}
}

func runDBAdd(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("db add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "数据库目标 ID")
	driver := fs.String("driver", "mysql", "数据库 driver，当前仅支持 mysql")
	host := fs.String("host", "", "数据库主机名或 IP")
	port := fs.Int("port", 3306, "数据库端口")
	database := fs.String("database", "", "数据库名")
	username := fs.String("user", "", "数据库用户名")
	timeoutSeconds := fs.Int("timeout", config.DefaultTimeoutSeconds, "默认超时秒数")
	maxOutputBytes := fs.Int64("max-output", config.DefaultMaxOutputBytes, "默认最大输出字节数")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, masterKey, err := loadConfigAndVerifyMaster(store, stdout)
	if err != nil {
		return writeError(stderr, err)
	}
	if *id == "" || *host == "" || *database == "" || *username == "" {
		return writeError(stderr, fmt.Errorf("--id、--host、--database、--user 均不能为空"))
	}
	if *driver != "mysql" {
		return writeError(stderr, fmt.Errorf("当前只支持 mysql driver"))
	}
	if _, ok := cfg.FindDBTarget(*id); ok {
		return writeError(stderr, fmt.Errorf("数据库目标 %q 已存在", *id))
	}

	password, err := promptHiddenRequired(stdout, "请输入 MySQL 密码: ", "MySQL 密码")
	if err != nil {
		return writeError(stderr, err)
	}
	secrets, err := store.LoadSecrets(masterKey)
	if err != nil {
		return writeError(stderr, err)
	}
	cfg.DBTargets = append(cfg.DBTargets, config.DBTarget{
		ID:                    *id,
		Driver:                *driver,
		Host:                  *host,
		Port:                  *port,
		Database:              *database,
		Username:              *username,
		DefaultTimeoutSeconds: defaultTimeoutSeconds(*timeoutSeconds),
		MaxOutputBytes:        defaultMaxOutputBytes(*maxOutputBytes),
	})
	secrets.DB[*id] = config.DBSecret{Password: password}
	if err := store.SaveSecrets(masterKey, secrets); err != nil {
		return writeError(stderr, err)
	}
	if err := store.SaveConfig(cfg); err != nil {
		return writeError(stderr, err)
	}
	auditID := writeAudit(store, audit.Event{Action: "db.add", Target: *id, OK: true})
	return writeValue(stdout, opts.Format, map[string]any{"ok": true, "target": *id, "audit_id": auditID})
}

func runDBTemplateAdd(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("db template add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fromFile := fs.String("from-file", "", "从 JSON 文件读取 DB 模板")
	targetID := fs.String("target", "", "数据库目标 ID")
	name := fs.String("name", "", "模板名")
	sqlText := fs.String("sql", "", "SQL 模板")
	kind := fs.String("kind", policy.SQLKindRead, "SQL 类型：read 或 write")
	timeoutSeconds := fs.Int("timeout", config.DefaultTimeoutSeconds, "模板超时秒数")
	maxOutputBytes := fs.Int64("max-output", config.DefaultMaxOutputBytes, "模板最大输出字节数")
	description := fs.String("description", "", "模板说明")
	var params multiFlag
	fs.Var(&params, "param", "参数规则，例如 id:int")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, _, err := loadConfigAndVerifyMaster(store, stdout)
	if err != nil {
		return writeError(stderr, err)
	}
	tmpl, err := loadDBTemplateFromFlags(*fromFile, *targetID, *name, *sqlText, *kind, *timeoutSeconds, *maxOutputBytes, *description, []string(params))
	if err != nil {
		return writeError(stderr, err)
	}
	if _, ok := cfg.FindDBTarget(tmpl.Target); !ok {
		return writeError(stderr, fmt.Errorf("数据库目标 %q 不存在", tmpl.Target))
	}
	if _, exists := cfg.FindDBTemplate(tmpl.Target, tmpl.Name); exists {
		return writeError(stderr, fmt.Errorf("数据库模板 %q 已存在", tmpl.Name))
	}
	if err := policy.ValidateSQLExecution(tmpl.SQL, tmpl.Kind); err != nil {
		return writeError(stderr, err)
	}
	cfg.DBTemplates = append(cfg.DBTemplates, tmpl)
	if err := store.SaveConfig(cfg); err != nil {
		return writeError(stderr, err)
	}
	auditID := writeAudit(store, audit.Event{Action: "db.template.add", Target: tmpl.Target, Template: tmpl.Name, OK: true})
	return writeValue(stdout, opts.Format, map[string]any{"ok": true, "target": tmpl.Target, "template": tmpl.Name, "audit_id": auditID})
}

func runDBExec(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("db exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "数据库目标 ID")
	templateName := fs.String("template", "", "模板名")
	var params multiFlag
	fs.Var(&params, "param", "模板参数，格式 key=value")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	start := time.Now()
	callParams, err := parseKeyValueParams(params)
	if err != nil {
		return writeError(stderr, err)
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	target, ok := cfg.FindDBTarget(*targetID)
	if !ok {
		return writeError(stderr, fmt.Errorf("数据库目标 %q 不存在", *targetID))
	}
	tmpl, ok := cfg.FindDBTemplate(*targetID, *templateName)
	if !ok {
		return writeError(stderr, fmt.Errorf("数据库模板 %q 不存在", *templateName))
	}
	rendered, err := safetemplate.RenderSQLTemplate(tmpl.SQL, tmpl.Params, callParams)
	if err != nil {
		return writeError(stderr, err)
	}
	if err := policy.ValidateSQLExecution(rendered.Query, tmpl.Kind); err != nil {
		return writeError(stderr, err)
	}
	secrets, _, err := loadExecutionSecrets(store)
	if err != nil {
		return writeError(stderr, err)
	}
	result, execErr := dbclient.Execute(context.Background(), target, secrets.DB[target.ID], rendered.Query, rendered.Args, tmpl.Kind, time.Duration(defaultTimeoutSeconds(tmpl.TimeoutSeconds))*time.Second, defaultMaxOutputBytes(tmpl.MaxOutputBytes))
	response := map[string]any{
		"ok":          execErr == nil,
		"target":      target.ID,
		"template":    tmpl.Name,
		"duration_ms": time.Since(start).Milliseconds(),
		"result":      result,
		"truncated":   result.Truncated,
	}
	if execErr != nil {
		response["error"] = execErr.Error()
	}
	auditID := writeAudit(store, audit.Event{Action: "db.exec", Target: target.ID, Template: tmpl.Name, Params: callParams, OK: execErr == nil, DurationMS: time.Since(start).Milliseconds(), ErrorClass: errorClass(execErr)})
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	if execErr != nil {
		return 1
	}
	return 0
}

func loadDBTemplateFromFlags(fromFile string, targetID string, name string, sqlText string, kind string, timeoutSeconds int, maxOutputBytes int64, description string, params []string) (config.DBTemplate, error) {
	if fromFile != "" {
		data, err := os.ReadFile(fromFile)
		if err != nil {
			return config.DBTemplate{}, fmt.Errorf("读取模板文件失败: %w", err)
		}
		var tmpl config.DBTemplate
		if err := json.Unmarshal(data, &tmpl); err != nil {
			return config.DBTemplate{}, fmt.Errorf("解析模板 JSON 失败: %w", err)
		}
		return normalizeDBTemplate(tmpl)
	}
	rules, err := parseParamRules(params)
	if err != nil {
		return config.DBTemplate{}, err
	}
	return normalizeDBTemplate(config.DBTemplate{
		Name:           name,
		Target:         targetID,
		SQL:            sqlText,
		Kind:           kind,
		Params:         rules,
		TimeoutSeconds: timeoutSeconds,
		MaxOutputBytes: maxOutputBytes,
		Description:    description,
	})
}

func normalizeDBTemplate(tmpl config.DBTemplate) (config.DBTemplate, error) {
	if tmpl.Target == "" || tmpl.Name == "" || tmpl.SQL == "" {
		return config.DBTemplate{}, fmt.Errorf("数据库模板 target、name、sql 均不能为空")
	}
	if tmpl.Kind == "" {
		tmpl.Kind = policy.SQLKindRead
	}
	if tmpl.Kind != policy.SQLKindRead && tmpl.Kind != policy.SQLKindWrite {
		return config.DBTemplate{}, fmt.Errorf("SQL 模板 kind 只支持 read 或 write")
	}
	if tmpl.Params == nil {
		tmpl.Params = map[string]safetemplate.ParamRule{}
	}
	tmpl.TimeoutSeconds = defaultTimeoutSeconds(tmpl.TimeoutSeconds)
	tmpl.MaxOutputBytes = defaultMaxOutputBytes(tmpl.MaxOutputBytes)
	return tmpl, nil
}
