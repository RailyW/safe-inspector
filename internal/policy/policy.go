// Package policy 提供 safe-inspector 的执行策略校验。
//
// 模板渲染只负责“参数是否安全地进入模板”；本包负责判断渲染后的 SQL
// 或 sudo 使用方式是否符合第一版产品边界。
package policy

import (
	"fmt"

	"github.com/RailyW/safe-inspector/internal/risk"
)

const (
	SQLKindRead  = "read"
	SQLKindWrite = "write"
)

// ClassifySQLRisk 返回 SQL 的风险分级，供 CLI 解释拒绝或审批原因。
func ClassifySQLRisk(query string) risk.Assessment {
	return risk.ClassifySQL(query)
}

// ValidateTemplateSQLExecution 校验模板 SQL 是否符合模板声明的读写类型。
func ValidateTemplateSQLExecution(query string, kind string) error {
	return ValidateSQLExecution(query, kind)
}

// ValidateSQLExecution 校验 SQL 是否符合模板声明的读写类型。
// 第一版允许 SELECT/SHOW/DESCRIBE/EXPLAIN 读查询；INSERT/UPDATE/DELETE 只有
// kind=write 的模板可执行；DDL/DCL 和多语句始终拒绝。
func ValidateSQLExecution(query string, kind string) error {
	if kind != "" && kind != SQLKindRead && kind != SQLKindWrite {
		return fmt.Errorf("未知 SQL 模板类型 %q", kind)
	}
	assessment := risk.ClassifySQL(query)
	switch assessment.Decision {
	case risk.DecisionAllow:
		return nil
	case risk.DecisionTemplateRequired:
		if kind == SQLKindWrite {
			return nil
		}
		return fmt.Errorf("SQL 风险等级 %s 需要 write 模板审批: %s", assessment.Level, stringsJoinReasons(assessment.Reasons))
	default:
		return fmt.Errorf("SQL 风险等级 %s 被拒绝: %s", assessment.Level, stringsJoinReasons(assessment.Reasons))
	}
}

// ValidateSudoPolicy 确认 sudo 模板只能在目标机器显式允许 sudo 时执行。
func ValidateSudoPolicy(targetAllowsSudo bool, templateUsesSudo bool) error {
	if templateUsesSudo && !targetAllowsSudo {
		return fmt.Errorf("模板要求 sudo，但目标机器未开启 allow_sudo")
	}
	return nil
}

func stringsJoinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "无具体原因"
	}
	result := reasons[0]
	for _, reason := range reasons[1:] {
		result += "；" + reason
	}
	return result
}
