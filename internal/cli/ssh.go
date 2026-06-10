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
	"github.com/RailyW/safe-inspector/internal/policy"
	"github.com/RailyW/safe-inspector/internal/risk"
	"github.com/RailyW/safe-inspector/internal/safetemplate"
	"github.com/RailyW/safe-inspector/internal/sshclient"
)

// sshExecute 是 SSH 实际执行函数的注入点。
//
// 生产环境默认调用 sshclient.Execute；测试会替换它，避免连接真实机器。
var sshExecute = sshclient.Execute

func runSSH(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "ssh 缺少子命令：add、template add、exec、run、risk")
		return 2
	}
	switch args[0] {
	case "add":
		return runSSHAdd(store, opts, args[1:], stdout, stderr)
	case "template":
		if len(args) >= 2 && args[1] == "add" {
			return runSSHTemplateAdd(store, opts, args[2:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "ssh template 仅支持 add")
		return 2
	case "exec":
		return runSSHExec(store, opts, args[1:], stdout, stderr)
	case "run":
		return runSSHRun(store, opts, args[1:], stdout, stderr)
	case "risk":
		return runSSHRisk(store, opts, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知 ssh 子命令: %s\n", args[0])
		return 2
	}
}

func runSSHAdd(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("ssh add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "SSH 目标 ID")
	host := fs.String("host", "", "SSH 主机名或 IP")
	port := fs.Int("port", 22, "SSH 端口")
	user := fs.String("user", "", "SSH 用户")
	authType := fs.String("auth", "password", "认证类型：password 或 key")
	keyPath := fs.String("key-path", "", "SSH 私钥路径")
	allowSudo := fs.Bool("allow-sudo", false, "是否允许 sudo 模板")
	allowAdhocLowRisk := fs.Bool("allow-adhoc-low-risk", false, "是否允许低风险观测命令临时执行")
	withKeyPassphrase := fs.Bool("with-key-passphrase", false, "是否提示输入 SSH 私钥 passphrase")
	timeoutSeconds := fs.Int("timeout", config.DefaultTimeoutSeconds, "默认超时秒数")
	maxOutputBytes := fs.Int64("max-output", config.DefaultMaxOutputBytes, "默认最大输出字节数")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, masterKey, err := loadConfigAndVerifyMaster(store, stdout)
	if err != nil {
		return writeError(stderr, err)
	}
	if *id == "" || *host == "" || *user == "" {
		return writeError(stderr, fmt.Errorf("--id、--host、--user 均不能为空"))
	}
	if _, ok := cfg.FindSSHTarget(*id); ok {
		return writeError(stderr, fmt.Errorf("SSH 目标 %q 已存在", *id))
	}

	secrets, err := store.LoadSecrets(masterKey)
	if err != nil {
		return writeError(stderr, err)
	}
	secret := config.SSHSecret{}
	switch *authType {
	case "password":
		secret.Password, err = promptHiddenRequired(stdout, "请输入 SSH 密码: ", "SSH 密码")
	case "key":
		if *keyPath == "" {
			return writeError(stderr, fmt.Errorf("key 认证必须提供 --key-path"))
		}
		if *withKeyPassphrase {
			secret.KeyPassphrase, err = promptHiddenRequired(stdout, "请输入 SSH 私钥 passphrase: ", "SSH 私钥 passphrase")
		}
	default:
		return writeError(stderr, fmt.Errorf("--auth 只支持 password 或 key"))
	}
	if err != nil {
		return writeError(stderr, err)
	}
	if *allowSudo {
		secret.SudoPassword, err = promptHiddenRequired(stdout, "请输入 sudo 密码: ", "sudo 密码")
		if err != nil {
			return writeError(stderr, err)
		}
	}

	adhocPolicy := config.AdhocPolicy{}
	if *allowAdhocLowRisk {
		adhocPolicy = config.AdhocPolicy{Enabled: true, MaxRisk: config.AdhocRiskLow, Profile: config.SSHAdhocProfileObservability}
	}
	cfg.SSHTargets = append(cfg.SSHTargets, config.SSHTarget{
		ID:                    *id,
		Host:                  *host,
		Port:                  *port,
		User:                  *user,
		AuthType:              *authType,
		KeyPath:               *keyPath,
		AllowSudo:             *allowSudo,
		DefaultTimeoutSeconds: defaultTimeoutSeconds(*timeoutSeconds),
		MaxOutputBytes:        defaultMaxOutputBytes(*maxOutputBytes),
		AdhocPolicy:           adhocPolicy,
	})
	secrets.SSH[*id] = secret
	if err := store.SaveSecrets(masterKey, secrets); err != nil {
		return writeError(stderr, err)
	}
	if err := store.SaveConfig(cfg); err != nil {
		return writeError(stderr, err)
	}
	auditID := writeAudit(store, audit.Event{Action: "ssh.add", Target: *id, OK: true})
	return writeValue(stdout, opts.Format, map[string]any{"ok": true, "target": *id, "audit_id": auditID})
}

func runSSHTemplateAdd(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("ssh template add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fromFile := fs.String("from-file", "", "从 JSON 文件读取 SSH 模板")
	targetID := fs.String("target", "", "SSH 目标 ID")
	name := fs.String("name", "", "模板名")
	command := fs.String("command", "", "命令模板")
	sudo := fs.Bool("sudo", false, "该模板是否使用 sudo")
	timeoutSeconds := fs.Int("timeout", config.DefaultTimeoutSeconds, "模板超时秒数")
	maxOutputBytes := fs.Int64("max-output", config.DefaultMaxOutputBytes, "模板最大输出字节数")
	description := fs.String("description", "", "模板说明")
	var params multiFlag
	fs.Var(&params, "param", "参数规则，例如 service:enum=nginx,mysql")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, _, err := loadConfigAndVerifyMaster(store, stdout)
	if err != nil {
		return writeError(stderr, err)
	}
	tmpl, err := loadSSHTemplateFromFlags(*fromFile, *targetID, *name, *command, *sudo, *timeoutSeconds, *maxOutputBytes, *description, []string(params))
	if err != nil {
		return writeError(stderr, err)
	}
	target, ok := cfg.FindSSHTarget(tmpl.Target)
	if !ok {
		return writeError(stderr, fmt.Errorf("SSH 目标 %q 不存在", tmpl.Target))
	}
	if _, exists := cfg.FindSSHTemplate(tmpl.Target, tmpl.Name); exists {
		return writeError(stderr, fmt.Errorf("SSH 模板 %q 已存在", tmpl.Name))
	}
	if err := policy.ValidateSudoPolicy(target.AllowSudo, tmpl.Sudo); err != nil {
		return writeError(stderr, err)
	}
	cfg.SSHTemplates = append(cfg.SSHTemplates, tmpl)
	if err := store.SaveConfig(cfg); err != nil {
		return writeError(stderr, err)
	}
	auditID := writeAudit(store, audit.Event{Action: "ssh.template.add", Target: tmpl.Target, Template: tmpl.Name, OK: true})
	return writeValue(stdout, opts.Format, map[string]any{"ok": true, "target": tmpl.Target, "template": tmpl.Name, "audit_id": auditID})
}

func runSSHExec(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("ssh exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "SSH 目标 ID")
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
	target, ok := cfg.FindSSHTarget(*targetID)
	if !ok {
		return writeError(stderr, fmt.Errorf("SSH 目标 %q 不存在", *targetID))
	}
	tmpl, ok := cfg.FindSSHTemplate(*targetID, *templateName)
	if !ok {
		return writeError(stderr, fmt.Errorf("SSH 模板 %q 不存在", *templateName))
	}
	if err := policy.ValidateSudoPolicy(target.AllowSudo, tmpl.Sudo); err != nil {
		return writeError(stderr, err)
	}
	command, err := safetemplate.RenderShellTemplate(tmpl.Command, tmpl.Params, callParams)
	if err != nil {
		return writeError(stderr, err)
	}
	secrets, _, err := loadExecutionSecrets(store)
	if err != nil {
		return writeError(stderr, err)
	}
	secret := secrets.SSH[target.ID]
	result, execErr := sshclient.Execute(context.Background(), target, secret, command, tmpl.Sudo, time.Duration(defaultTimeoutSeconds(tmpl.TimeoutSeconds))*time.Second, defaultMaxOutputBytes(tmpl.MaxOutputBytes))
	response := map[string]any{
		"ok":          execErr == nil,
		"target":      target.ID,
		"template":    tmpl.Name,
		"duration_ms": time.Since(start).Milliseconds(),
		"stdout":      result.Stdout,
		"stderr":      result.Stderr,
		"exit_code":   result.ExitCode,
		"truncated":   result.Truncated,
	}
	if execErr != nil {
		response["error"] = execErr.Error()
	}
	auditID := writeAudit(store, audit.Event{Action: "ssh.exec", Target: target.ID, Template: tmpl.Name, Params: callParams, OK: execErr == nil, DurationMS: time.Since(start).Milliseconds(), ErrorClass: errorClass(execErr)})
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	if execErr != nil {
		return 1
	}
	return 0
}

// runSSHRisk 只解释 SSH 命令风险，不连接远程机器。
//
// 该命令用于 agent 在执行前探测边界：低风险说明可以尝试 ssh run；
// 中风险会返回模板审批建议；高风险/关键风险会返回拒绝原因。
func runSSHRisk(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("ssh risk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "SSH 目标 ID")
	command := fs.String("command", "", "待评估的 SSH 命令")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	start := time.Now()
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	if _, ok := cfg.FindSSHTarget(*targetID); !ok {
		return writeError(stderr, fmt.Errorf("SSH 目标 %q 不存在", *targetID))
	}
	assessment := risk.ClassifySSHCommand(*command)
	response := map[string]any{"ok": true, "target": *targetID, "duration_ms": time.Since(start).Milliseconds()}
	addRiskFields(response, assessment)
	if assessment.Decision == risk.DecisionTemplateRequired {
		response["suggested_approval_command"] = suggestedSSHTemplateCommand(*targetID, *command)
	}
	auditID := writeAudit(store, audit.Event{
		Action:      "ssh.risk",
		Target:      *targetID,
		Params:      map[string]string{"command_sha256": hashSummary(*command)},
		RiskLevel:   string(assessment.Level),
		Decision:    string(assessment.Decision),
		RiskReasons: assessment.Reasons,
		OK:          true,
		DurationMS:  time.Since(start).Milliseconds(),
	})
	response["audit_id"] = auditID
	return writeValue(stdout, opts.Format, response)
}

// runSSHRun 执行低风险 SSH 临时命令。
//
// 它先进行确定性风险分级：只有低风险 allow 且目标开启 adhoc_policy 时才会
// 解密认证信息并连接远程机器；中风险和高风险都不会连接远程机器。
func runSSHRun(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("ssh run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetID := fs.String("target", "", "SSH 目标 ID")
	command := fs.String("command", "", "待执行的 SSH 命令")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	start := time.Now()
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	target, ok := cfg.FindSSHTarget(*targetID)
	if !ok {
		return writeError(stderr, fmt.Errorf("SSH 目标 %q 不存在", *targetID))
	}
	assessment := risk.ClassifySSHCommand(*command)
	if assessment.Decision == risk.DecisionTemplateRequired {
		return writeSSHAdhocDecision(store, opts, stdout, start, target.ID, *command, assessment, suggestedSSHTemplateCommand(target.ID, *command), 0)
	}
	if assessment.Decision == risk.DecisionDeny {
		return writeSSHAdhocDecision(store, opts, stdout, start, target.ID, *command, assessment, "", 1)
	}
	adhocPolicy := target.NormalizedAdhocPolicy()
	if !adhocPolicy.Enabled {
		assessment = deniedByAdhocPolicy(assessment, "目标未开启 adhoc_policy，低风险临时执行被拒绝")
		return writeSSHAdhocDecision(store, opts, stdout, start, target.ID, *command, assessment, "", 1)
	}
	if !risk.Allows(adhocPolicy.MaxRisk, assessment.Level) {
		assessment = deniedByAdhocPolicy(assessment, fmt.Sprintf("目标 adhoc_policy 只允许最高风险等级 %s", adhocPolicy.MaxRisk))
		return writeSSHAdhocDecision(store, opts, stdout, start, target.ID, *command, assessment, "", 1)
	}

	secrets, _, err := loadExecutionSecrets(store)
	if err != nil {
		return writeError(stderr, err)
	}
	result, execErr := sshExecute(context.Background(), target, secrets.SSH[target.ID], *command, false, time.Duration(defaultTimeoutSeconds(target.DefaultTimeoutSeconds))*time.Second, defaultMaxOutputBytes(target.MaxOutputBytes))
	response := map[string]any{
		"ok":          execErr == nil,
		"target":      target.ID,
		"duration_ms": time.Since(start).Milliseconds(),
		"stdout":      result.Stdout,
		"stderr":      result.Stderr,
		"exit_code":   result.ExitCode,
		"truncated":   result.Truncated,
	}
	addRiskFields(response, assessment)
	if execErr != nil {
		response["error"] = execErr.Error()
	}
	auditID := writeAudit(store, audit.Event{
		Action:      "ssh.run",
		Target:      target.ID,
		Params:      map[string]string{"command_sha256": hashSummary(*command)},
		RiskLevel:   string(assessment.Level),
		Decision:    string(assessment.Decision),
		RiskReasons: assessment.Reasons,
		OK:          execErr == nil,
		DurationMS:  time.Since(start).Milliseconds(),
		ErrorClass:  errorClass(execErr),
	})
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	if execErr != nil {
		return 1
	}
	return 0
}

// writeSSHAdhocDecision 输出未执行 SSH 命令时的结构化风险结果并写审计。
func writeSSHAdhocDecision(store config.Store, opts globalOptions, stdout io.Writer, start time.Time, targetID string, command string, assessment risk.Assessment, suggestion string, exitCode int) int {
	response := map[string]any{"ok": false, "target": targetID, "duration_ms": time.Since(start).Milliseconds()}
	addRiskFields(response, assessment)
	if suggestion != "" {
		response["suggested_approval_command"] = suggestion
	}
	auditID := writeAudit(store, audit.Event{
		Action:      "ssh.run",
		Target:      targetID,
		Params:      map[string]string{"command_sha256": hashSummary(command)},
		RiskLevel:   string(assessment.Level),
		Decision:    string(assessment.Decision),
		RiskReasons: assessment.Reasons,
		OK:          false,
		DurationMS:  time.Since(start).Milliseconds(),
	})
	response["audit_id"] = auditID
	writeValue(stdout, opts.Format, response)
	return exitCode
}

func loadSSHTemplateFromFlags(fromFile string, targetID string, name string, command string, sudo bool, timeoutSeconds int, maxOutputBytes int64, description string, params []string) (config.SSHTemplate, error) {
	if fromFile != "" {
		data, err := os.ReadFile(fromFile)
		if err != nil {
			return config.SSHTemplate{}, fmt.Errorf("读取模板文件失败: %w", err)
		}
		var tmpl config.SSHTemplate
		if err := json.Unmarshal(data, &tmpl); err != nil {
			return config.SSHTemplate{}, fmt.Errorf("解析模板 JSON 失败: %w", err)
		}
		return normalizeSSHTemplate(tmpl)
	}
	rules, err := parseParamRules(params)
	if err != nil {
		return config.SSHTemplate{}, err
	}
	return normalizeSSHTemplate(config.SSHTemplate{
		Name:           name,
		Target:         targetID,
		Command:        command,
		Params:         rules,
		Sudo:           sudo,
		TimeoutSeconds: timeoutSeconds,
		MaxOutputBytes: maxOutputBytes,
		Description:    description,
	})
}

func normalizeSSHTemplate(tmpl config.SSHTemplate) (config.SSHTemplate, error) {
	if tmpl.Target == "" || tmpl.Name == "" || tmpl.Command == "" {
		return config.SSHTemplate{}, fmt.Errorf("SSH 模板 target、name、command 均不能为空")
	}
	if tmpl.Params == nil {
		tmpl.Params = map[string]safetemplate.ParamRule{}
	}
	tmpl.TimeoutSeconds = defaultTimeoutSeconds(tmpl.TimeoutSeconds)
	tmpl.MaxOutputBytes = defaultMaxOutputBytes(tmpl.MaxOutputBytes)
	return tmpl, nil
}

func errorClass(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T", err)
}
