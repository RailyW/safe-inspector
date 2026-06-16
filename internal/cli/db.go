package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/RailyW/safe-inspector/internal/approval"
	"github.com/RailyW/safe-inspector/internal/audit"
	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/dbclient"
	"github.com/RailyW/safe-inspector/internal/policy"
	"github.com/RailyW/safe-inspector/internal/risk"
	"github.com/RailyW/safe-inspector/internal/safetemplate"
)

// dbExecute 是数据库实际执行函数的注入点。
//
// 生产环境默认调用 dbclient.Execute；测试会替换它，避免连接真实 MySQL。
var dbExecute = dbclient.Execute

// dbExecuteApproved 是 LLM/danger 已审批 SQL 的执行注入点。
//
// 它默认调用 dbclient.ExecuteApproved，不再套用 classic SQL 风险校验。
var dbExecuteApproved = dbclient.ExecuteApproved

func runDB(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "db 缺少子命令：add、template add、exec、query、risk")
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
	case "query":
		return runDBQuery(store, opts, args[1:], stdout, stderr)
	case "risk":
		return runDBRisk(store, opts, args[1:], stdout, stderr)
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
	allowAdhocLowRisk := fs.Bool("allow-adhoc-low-risk", false, "是否允许低风险只读 SQL 临时执行")
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
	adhocPolicy := config.AdhocPolicy{}
	if *allowAdhocLowRisk {
		adhocPolicy = config.AdhocPolicy{Enabled: true, MaxRisk: config.AdhocRiskLow, Profile: config.DBAdhocProfileReadOnly}
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
		AdhocPolicy:           adhocPolicy,
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
	assessment := risk.ClassifySQL(rendered.Query)
	approvalCfg := cfg.NormalizedApproval()
	approvalResult := approval.Result{}
	var reviewErr error
	execute := dbExecute
	if approvalCfg.Mode == config.ApprovalModeClassic {
		if err := policy.ValidateSQLExecution(rendered.Query, tmpl.Kind); err != nil {
			return writeError(stderr, err)
		}
		approvalResult = classicApprovalResult(risk.Assessment{Level: risk.LevelLow, Decision: risk.DecisionAllow, Reasons: []string{"已批准 SQL 模板执行"}})
	} else {
		execute = dbExecuteApproved
		approvalResult, reviewErr = reviewExecution(context.Background(), cfg, approval.Request{
			Operation:    approval.OperationDBExec,
			TargetID:     target.ID,
			TemplateName: tmpl.Name,
			SQL:          rendered.Query,
			SQLKind:      tmpl.Kind,
			Params:       callParams,
			ClassicRisk:  assessment,
		})
		if approvalResult.Decision != risk.DecisionAllow {
			response := map[string]any{
				"ok":          false,
				"target":      target.ID,
				"template":    tmpl.Name,
				"duration_ms": time.Since(start).Milliseconds(),
			}
			addApprovalFields(response, approvalResult)
			if reviewErr != nil {
				response["error"] = reviewErr.Error()
			}
			auditID := writeAudit(store, approvalAuditFields(audit.Event{Action: "db.exec", Target: target.ID, Template: tmpl.Name, Params: callParams, OK: false, DurationMS: time.Since(start).Milliseconds(), ErrorClass: errorClass(reviewErr)}, approvalResult))
			response["audit_id"] = auditID
			writeValue(stdout, opts.Format, response)
			return 1
		}
	}
	secrets, _, err := loadExecutionSecrets(store)
	if err != nil {
		return writeError(stderr, err)
	}
	result, execErr := execute(context.Background(), target, secrets.DB[target.ID], rendered.Query, rendered.Args, tmpl.Kind, time.Duration(defaultTimeoutSeconds(tmpl.TimeoutSeconds))*time.Second, defaultMaxOutputBytes(tmpl.MaxOutputBytes))
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
	addApprovalFields(response, approvalResult)
	auditID := writeAudit(store, approvalAuditFields(audit.Event{Action: "db.exec", Target: target.ID, Template: tmpl.Name, Params: callParams, OK: execErr == nil, DurationMS: time.Since(start).Milliseconds(), ErrorClass: errorClass(execErr)}, approvalResult))
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	if execErr != nil {
		return 1
	}
	return 0
}

// runDBRisk 只解释 SQL 风险，不连接数据库。
//
// 该命令适合 agent 在执行前判断边界：低风险表示可尝试 db query；
// 中风险返回模板审批建议；高风险/关键风险返回拒绝原因。
func runDBRisk(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("db risk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "数据库目标 ID")
	sqlText := fs.String("sql", "", "待评估的 SQL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	start := time.Now()
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	if _, ok := cfg.FindDBTarget(*targetID); !ok {
		return writeError(stderr, fmt.Errorf("数据库目标 %q 不存在", *targetID))
	}
	assessment := risk.ClassifySQL(*sqlText)
	response := map[string]any{"ok": true, "target": *targetID, "duration_ms": time.Since(start).Milliseconds()}
	approvalResult := classicApprovalResult(assessment)
	var reviewErr error
	if cfg.NormalizedApproval().Mode == config.ApprovalModeClassic {
		if assessment.Decision == risk.DecisionTemplateRequired {
			approvalResult.SuggestedTemplate = suggestedDBTemplateCommand(*targetID, *sqlText, policy.SQLKindWrite)
		}
	} else {
		approvalResult, reviewErr = reviewExecution(context.Background(), cfg, approval.Request{
			Operation:   approval.OperationDBQuery,
			TargetID:    *targetID,
			SQL:         *sqlText,
			SQLKind:     inferAdhocSQLKind(*sqlText),
			ClassicRisk: assessment,
		})
		if reviewErr != nil {
			response["ok"] = false
			response["error"] = reviewErr.Error()
		}
	}
	addApprovalFields(response, approvalResult)
	auditID := writeAudit(store, approvalAuditFields(audit.Event{
		Action:     "db.risk",
		Target:     *targetID,
		Params:     map[string]string{"sql_sha256": hashSummary(*sqlText)},
		OK:         reviewErr == nil,
		DurationMS: time.Since(start).Milliseconds(),
		ErrorClass: errorClass(reviewErr),
	}, approvalResult))
	response["audit_id"] = auditID
	return writeValue(stdout, opts.Format, response)
}

// runDBQuery 执行低风险 SQL 临时查询。
//
// 它只会执行风险分级为 low/allow 的只读 SQL；写入类 SQL 返回模板审批建议，
// 危险 SQL 直接拒绝。只有真正允许执行时才会读取 SAFE_INSPECTOR_MASTER_KEY。
func runDBQuery(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("db query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "数据库目标 ID")
	sqlText := fs.String("sql", "", "待执行的 SQL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	start := time.Now()
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	target, ok := cfg.FindDBTarget(*targetID)
	if !ok {
		return writeError(stderr, fmt.Errorf("数据库目标 %q 不存在", *targetID))
	}
	assessment := risk.ClassifySQL(*sqlText)
	approvalCfg := cfg.NormalizedApproval()
	approvalResult := classicApprovalResult(assessment)
	execute := dbExecute
	sqlKind := policy.SQLKindRead
	var reviewErr error
	if approvalCfg.Mode == config.ApprovalModeClassic {
		if assessment.Decision == risk.DecisionTemplateRequired {
			approvalResult.SuggestedTemplate = suggestedDBTemplateCommand(target.ID, *sqlText, policy.SQLKindWrite)
			return writeDBAdhocDecision(store, opts, stdout, start, target.ID, *sqlText, approvalResult, 0, nil)
		}
		if assessment.Decision == risk.DecisionDeny {
			return writeDBAdhocDecision(store, opts, stdout, start, target.ID, *sqlText, approvalResult, 1, nil)
		}
		adhocPolicy := target.NormalizedAdhocPolicy()
		if !adhocPolicy.Enabled {
			assessment = deniedByAdhocPolicy(assessment, "目标未开启 adhoc_policy，低风险临时查询被拒绝")
			return writeDBAdhocDecision(store, opts, stdout, start, target.ID, *sqlText, classicApprovalResult(assessment), 1, nil)
		}
		if !risk.Allows(adhocPolicy.MaxRisk, assessment.Level) {
			assessment = deniedByAdhocPolicy(assessment, fmt.Sprintf("目标 adhoc_policy 只允许最高风险等级 %s", adhocPolicy.MaxRisk))
			return writeDBAdhocDecision(store, opts, stdout, start, target.ID, *sqlText, classicApprovalResult(assessment), 1, nil)
		}
	} else {
		execute = dbExecuteApproved
		sqlKind = inferAdhocSQLKind(*sqlText)
		approvalResult, reviewErr = reviewExecution(context.Background(), cfg, approval.Request{
			Operation:   approval.OperationDBQuery,
			TargetID:    target.ID,
			SQL:         *sqlText,
			SQLKind:     sqlKind,
			ClassicRisk: assessment,
		})
		if approvalResult.Decision != risk.DecisionAllow {
			return writeDBAdhocDecision(store, opts, stdout, start, target.ID, *sqlText, approvalResult, 1, reviewErr)
		}
	}

	secrets, _, err := loadExecutionSecrets(store)
	if err != nil {
		return writeError(stderr, err)
	}
	result, execErr := execute(context.Background(), target, secrets.DB[target.ID], *sqlText, nil, sqlKind, time.Duration(defaultTimeoutSeconds(target.DefaultTimeoutSeconds))*time.Second, defaultMaxOutputBytes(target.MaxOutputBytes))
	response := map[string]any{
		"ok":          execErr == nil,
		"target":      target.ID,
		"duration_ms": time.Since(start).Milliseconds(),
		"result":      result,
		"truncated":   result.Truncated,
	}
	addApprovalFields(response, approvalResult)
	if execErr != nil {
		response["error"] = execErr.Error()
	}
	auditID := writeAudit(store, approvalAuditFields(audit.Event{
		Action:     "db.query",
		Target:     target.ID,
		Params:     map[string]string{"sql_sha256": hashSummary(*sqlText)},
		OK:         execErr == nil,
		DurationMS: time.Since(start).Milliseconds(),
		ErrorClass: errorClass(execErr),
	}, approvalResult))
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	if execErr != nil {
		return 1
	}
	return 0
}

// writeDBAdhocDecision 输出未执行 SQL 时的结构化风险结果并写审计。
func writeDBAdhocDecision(store config.Store, opts globalOptions, stdout io.Writer, start time.Time, targetID string, sqlText string, approvalResult approval.Result, exitCode int, reviewErr error) int {
	response := map[string]any{"ok": false, "target": targetID, "duration_ms": time.Since(start).Milliseconds()}
	addApprovalFields(response, approvalResult)
	if reviewErr != nil {
		response["error"] = reviewErr.Error()
	}
	auditID := writeAudit(store, approvalAuditFields(audit.Event{
		Action:     "db.query",
		Target:     targetID,
		Params:     map[string]string{"sql_sha256": hashSummary(sqlText)},
		OK:         false,
		DurationMS: time.Since(start).Milliseconds(),
		ErrorClass: errorClass(reviewErr),
	}, approvalResult))
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	return exitCode
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

// inferAdhocSQLKind 在 LLM/danger 模式下为临时 SQL 选择 Query 或 Exec。
//
// classic 模式不会使用该函数；它仍然由 deterministic policy 保证只读查询。
// 非只读首词统一归为 write，让 MySQL driver 通过 ExecContext 处理。
func inferAdhocSQLKind(sqlText string) string {
	fields := strings.Fields(strings.TrimSpace(sqlText))
	if len(fields) == 0 {
		return policy.SQLKindRead
	}
	switch strings.ToUpper(fields[0]) {
	case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN":
		return policy.SQLKindRead
	default:
		return policy.SQLKindWrite
	}
}
