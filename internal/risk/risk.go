// Package risk 提供 SSH 命令和 SQL 语句的确定性风险分级。
//
// 本包不连接任何远程资源，也不读取 secret。它只根据输入文本输出风险等级、
// 决策和原因，供 CLI 在执行前判断“允许临时执行、建议模板审批、直接拒绝”。
package risk

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Level 是临时执行风险等级，等级越高越不应自动执行。
type Level string

const (
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

// Decision 是风险评估之后给 CLI 的动作建议。
type Decision string

const (
	DecisionAllow            Decision = "allow"
	DecisionTemplateRequired Decision = "template_required"
	DecisionDeny             Decision = "deny"
)

// Assessment 是一次 SSH/SQL 风险评估的结构化结果。
type Assessment struct {
	Level    Level    `json:"risk_level"`
	Decision Decision `json:"decision"`
	Reasons  []string `json:"risk_reasons"`
}

var (
	sqlLeadingComment = regexp.MustCompile(`(?is)^\s*(/\*.*?\*/\s*|--[^\n]*\n\s*)*`)
	sqlSpace          = regexp.MustCompile(`\s+`)
	serviceName       = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)
	safeToken         = regexp.MustCompile(`^[A-Za-z0-9_@./:=,+%-]+$`)
	envAssignment     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// ClassifySQL 对一次临时 SQL 查询做风险分级。
//
// 第一版只有只读单语句会返回 allow；DML 返回 template_required；DDL/DCL、
// 多语句、文件函数、事务/锁表/权限相关语句直接 deny。
func ClassifySQL(query string) Assessment {
	normalized := strings.TrimSpace(query)
	if normalized == "" {
		return deny(LevelCritical, "SQL 不能为空")
	}
	if containsMultipleStatements(normalized) {
		return deny(LevelCritical, "SQL 不允许包含多语句")
	}
	upper := strings.ToUpper(sqlSpace.ReplaceAllString(normalized, " "))
	if containsDeniedSQLFeature(upper) {
		return deny(LevelCritical, "SQL 包含文件读写、延迟、权限或高风险特性")
	}

	verb := firstSQLVerb(normalized)
	switch verb {
	case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN":
		return allow("只读 SQL 单语句")
	case "INSERT", "UPDATE", "DELETE":
		return templateRequired(LevelMedium, fmt.Sprintf("SQL 类型 %s 需要模板审批", verb))
	case "DROP", "ALTER", "TRUNCATE", "CREATE", "GRANT", "REVOKE", "RENAME":
		return deny(LevelCritical, fmt.Sprintf("SQL 类型 %s 属于 DDL/DCL，禁止临时执行", verb))
	case "LOCK", "UNLOCK", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "SET":
		return deny(LevelHigh, fmt.Sprintf("SQL 类型 %s 涉及事务、锁或会话状态，禁止临时执行", verb))
	case "":
		return deny(LevelCritical, "无法识别 SQL 类型")
	default:
		return deny(LevelHigh, fmt.Sprintf("SQL 类型 %s 不在临时执行允许范围内", verb))
	}
}

// ClassifySSHCommand 对一次临时 SSH 命令做风险分级。
//
// 第一版低风险范围只覆盖观测类命令；sudo、未知命令和复杂 shell 建议转模板；
// 破坏性、持久化变更、网络外传和服务变更命令直接拒绝。
func ClassifySSHCommand(command string) Assessment {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return deny(LevelCritical, "SSH 命令不能为空")
	}
	if containsDestructiveSSHWord(trimmed) {
		return deny(LevelCritical, "SSH 命令包含破坏性、持久化变更或网络外传动作")
	}
	if containsShellMeta(trimmed) {
		return templateRequired(LevelMedium, "SSH 命令包含 shell 复合语法，需要模板审批")
	}
	argv, err := splitShellWords(trimmed)
	if err != nil {
		return templateRequired(LevelMedium, "SSH 命令无法安全解析，需要模板审批")
	}
	if len(argv) == 0 {
		return deny(LevelCritical, "SSH 命令不能为空")
	}
	if envAssignment.MatchString(argv[0]) {
		return templateRequired(LevelMedium, "SSH 命令包含环境变量赋值，需要模板审批")
	}
	if argv[0] == "sudo" {
		if len(argv) > 1 && isDestructiveSSHArgv(argv[1:]) {
			return deny(LevelCritical, "sudo 包装了高风险命令，禁止临时执行")
		}
		return templateRequired(LevelMedium, "sudo 命令必须通过模板审批")
	}
	if isLowRiskSSHArgv(argv) {
		return allow("SSH 观测类命令")
	}
	return templateRequired(LevelMedium, "SSH 命令不在低风险观测 profile 中，需要模板审批")
}

// Allows 判断实际风险等级是否不超过配置允许的最大等级。
func Allows(maxRisk string, level Level) bool {
	return levelRank(level) <= levelRank(Level(strings.TrimSpace(maxRisk)))
}

func allow(reason string) Assessment {
	return Assessment{Level: LevelLow, Decision: DecisionAllow, Reasons: []string{reason}}
}

func templateRequired(level Level, reason string) Assessment {
	return Assessment{Level: level, Decision: DecisionTemplateRequired, Reasons: []string{reason}}
}

func deny(level Level, reason string) Assessment {
	return Assessment{Level: level, Decision: DecisionDeny, Reasons: []string{reason}}
}

func levelRank(level Level) int {
	switch level {
	case LevelLow:
		return 1
	case LevelMedium:
		return 2
	case LevelHigh:
		return 3
	case LevelCritical:
		return 4
	default:
		return 0
	}
}

func firstSQLVerb(query string) string {
	query = sqlLeadingComment.ReplaceAllString(query, "")
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(fields[0])
}

func containsMultipleStatements(query string) bool {
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range query {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ';':
			if !inSingle && !inDouble && strings.TrimSpace(query[i+1:]) != "" {
				return true
			}
		}
	}
	return false
}

func containsDeniedSQLFeature(upper string) bool {
	denied := []string{
		" INTO OUTFILE ",
		" INTO DUMPFILE ",
		" LOAD_FILE(",
		" BENCHMARK(",
		" SLEEP(",
		" MYSQL.USER",
		" INFORMATION_SCHEMA.USER_PRIVILEGES",
	}
	padded := " " + upper + " "
	for _, item := range denied {
		if strings.Contains(padded, item) {
			return true
		}
	}
	return false
}

func containsShellMeta(command string) bool {
	for _, r := range command {
		switch r {
		case '|', '&', ';', '<', '>', '$', '`', '\n', '\r', '*', '?', '[', ']', '(', ')':
			return true
		}
	}
	return false
}

func containsDestructiveSSHWord(command string) bool {
	argv, err := splitShellWordsLenient(command)
	if err != nil {
		return false
	}
	return isDestructiveSSHArgv(argv)
}

func isDestructiveSSHArgv(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	if argv[0] == "sudo" && len(argv) > 1 {
		return isDestructiveSSHArgv(argv[1:])
	}
	switch argv[0] {
	case "rm", "rmdir", "shred", "dd", "chmod", "chown", "chgrp", "mkfs", "mount", "umount",
		"useradd", "userdel", "usermod", "passwd", "iptables", "nft", "firewall-cmd",
		"reboot", "shutdown", "halt", "poweroff", "curl", "wget", "nc", "netcat", "scp", "rsync",
		"apt", "apt-get", "yum", "dnf", "apk", "pacman":
		return true
	case "systemctl":
		return len(argv) > 1 && matchesAny(argv[1], "restart", "stop", "disable", "enable", "mask", "unmask", "start", "reload")
	case "service":
		return len(argv) > 2 && matchesAny(argv[2], "restart", "stop", "start", "reload")
	default:
		return false
	}
}

func isLowRiskSSHArgv(argv []string) bool {
	switch argv[0] {
	case "date":
		return len(argv) <= 2 && allSafeTokens(argv[1:])
	case "hostname":
		return len(argv) <= 2 && allAllowed(argv[1:], "-f", "--fqdn", "-s", "--short", "-I", "--all-ip-addresses")
	case "uptime", "whoami":
		return len(argv) == 1
	case "id":
		return len(argv) <= 3 && allSafeTokens(argv[1:])
	case "uname":
		return len(argv) <= 2 && allFlagTokens(argv[1:])
	case "df", "free", "ps", "ss":
		return len(argv) <= 8 && allSafeTokens(argv[1:])
	case "systemctl":
		return isLowRiskSystemctl(argv)
	case "journalctl":
		return isLowRiskJournalctl(argv)
	default:
		return false
	}
}

func isLowRiskSystemctl(argv []string) bool {
	if len(argv) < 3 || argv[1] != "status" || !serviceName.MatchString(argv[2]) {
		return false
	}
	for _, arg := range argv[3:] {
		if !matchesAny(arg, "--no-pager", "--full", "-l") && !strings.HasPrefix(arg, "--lines=") {
			return false
		}
	}
	return true
}

func isLowRiskJournalctl(argv []string) bool {
	unitSeen := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if !safeToken.MatchString(arg) {
			return false
		}
		switch arg {
		case "-u", "--unit":
			i++
			if i >= len(argv) || !serviceName.MatchString(argv[i]) {
				return false
			}
			unitSeen = true
		case "-n", "--lines", "-p", "--priority", "--since", "--until":
			i++
			if i >= len(argv) || !safeToken.MatchString(argv[i]) {
				return false
			}
		case "--no-pager", "--utc", "-r", "--reverse":
		default:
			if strings.HasPrefix(arg, "--unit=") {
				unitSeen = serviceName.MatchString(strings.TrimPrefix(arg, "--unit="))
			} else if !(strings.HasPrefix(arg, "--lines=") || strings.HasPrefix(arg, "--priority=") ||
				strings.HasPrefix(arg, "--since=") || strings.HasPrefix(arg, "--until=")) {
				return false
			}
		}
	}
	return unitSeen
}

func allSafeTokens(args []string) bool {
	for _, arg := range args {
		if !safeToken.MatchString(arg) {
			return false
		}
	}
	return true
}

func allFlagTokens(args []string) bool {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") || !safeToken.MatchString(arg) {
			return false
		}
	}
	return true
}

func allAllowed(args []string, allowed ...string) bool {
	for _, arg := range args {
		if !matchesAny(arg, allowed...) {
			return false
		}
	}
	return true
}

func matchesAny(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func splitShellWordsLenient(command string) ([]string, error) {
	if strings.ContainsAny(command, "|&;<>$`") {
		replacer := strings.NewReplacer("|", " ", "&", " ", ";", " ", "<", " ", ">", " ")
		command = replacer.Replace(command)
	}
	return splitShellWords(command)
}

func splitShellWords(command string) ([]string, error) {
	var words []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
	}

	for _, r := range command {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		return nil, errors.New("命令以转义字符结尾")
	}
	if quote != 0 {
		return nil, errors.New("命令存在未闭合引号")
	}
	flush()
	return words, nil
}
