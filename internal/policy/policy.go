// Package policy 提供 safe-inspector 的执行策略校验。
//
// 模板渲染只负责“参数是否安全地进入模板”；本包负责判断渲染后的 SQL
// 或 sudo 使用方式是否符合第一版产品边界。
package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	SQLKindRead  = "read"
	SQLKindWrite = "write"
)

var sqlLeadingComment = regexp.MustCompile(`(?is)^\s*(/\*.*?\*/\s*|--[^\n]*\n\s*)*`)

// ValidateSQLExecution 校验 SQL 是否符合模板声明的读写类型。
// 第一版允许 SELECT/SHOW/DESCRIBE/EXPLAIN 读查询；INSERT/UPDATE/DELETE 只有
// kind=write 的模板可执行；DDL/DCL 和多语句始终拒绝。
func ValidateSQLExecution(query string, kind string) error {
	normalized := strings.TrimSpace(query)
	if normalized == "" {
		return errors.New("SQL 不能为空")
	}
	if containsMultipleStatements(normalized) {
		return errors.New("SQL 不允许包含多语句")
	}

	verb := firstSQLVerb(normalized)
	if verb == "" {
		return errors.New("无法识别 SQL 类型")
	}
	if isAlwaysDeniedSQLVerb(verb) {
		return fmt.Errorf("SQL 类型 %s 在第一版中被拒绝", verb)
	}

	switch verb {
	case "SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN":
		if kind != "" && kind != SQLKindRead && kind != SQLKindWrite {
			return fmt.Errorf("未知 SQL 模板类型 %q", kind)
		}
		return nil
	case "INSERT", "UPDATE", "DELETE":
		if kind != SQLKindWrite {
			return fmt.Errorf("SQL 类型 %s 必须使用 write 模板审批", verb)
		}
		return nil
	default:
		return fmt.Errorf("SQL 类型 %s 不在允许范围内", verb)
	}
}

// ValidateSudoPolicy 确认 sudo 模板只能在目标机器显式允许 sudo 时执行。
func ValidateSudoPolicy(targetAllowsSudo bool, templateUsesSudo bool) error {
	if templateUsesSudo && !targetAllowsSudo {
		return errors.New("模板要求 sudo，但目标机器未开启 allow_sudo")
	}
	return nil
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

func isAlwaysDeniedSQLVerb(verb string) bool {
	switch verb {
	case "DROP", "ALTER", "TRUNCATE", "CREATE", "GRANT", "REVOKE", "RENAME", "LOCK", "UNLOCK":
		return true
	default:
		return false
	}
}
