package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/RailyW/safe-inspector/internal/risk"
)

// addRiskFields 把风险评估结果写入 CLI JSON 响应。
//
// 所有临时执行与风险解释命令都使用同一组字段，便于大语言模型稳定解析。
func addRiskFields(response map[string]any, assessment risk.Assessment) {
	response["risk_level"] = string(assessment.Level)
	response["risk_reasons"] = assessment.Reasons
	response["decision"] = string(assessment.Decision)
}

// deniedByAdhocPolicy 在低风险命令本身允许、但目标未开启临时执行时生成拒绝结果。
//
// 这类拒绝不是命令文本危险，而是目标级权限边界不允许自动执行。
func deniedByAdhocPolicy(assessment risk.Assessment, reason string) risk.Assessment {
	reasons := append([]string{}, assessment.Reasons...)
	reasons = append(reasons, reason)
	return risk.Assessment{Level: assessment.Level, Decision: risk.DecisionDeny, Reasons: reasons}
}

// hashSummary 返回输入文本的 SHA-256 摘要，供审计日志记录而不落原文。
func hashSummary(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// powerShellQuote 使用 PowerShell 单引号规则包裹用户待审批文本。
//
// 建议命令会展示给用户复制执行，单引号内通过两个单引号表示字面单引号。
func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// suggestedSSHTemplateCommand 为中风险 SSH 命令生成用户可复制的模板审批命令。
func suggestedSSHTemplateCommand(targetID string, command string) string {
	return fmt.Sprintf("safe-inspector ssh template add --target %s --name APPROVE_NAME --command %s --description %s",
		powerShellQuote(targetID),
		powerShellQuote(command),
		powerShellQuote("由低摩擦临时执行风险评估生成，请审批后替换模板名"))
}

// suggestedDBTemplateCommand 为中风险 SQL 生成用户可复制的模板审批命令。
func suggestedDBTemplateCommand(targetID string, sqlText string, kind string) string {
	return fmt.Sprintf("safe-inspector db template add --target %s --name APPROVE_NAME --kind %s --sql %s --description %s",
		powerShellQuote(targetID),
		powerShellQuote(kind),
		powerShellQuote(sqlText),
		powerShellQuote("由低摩擦临时执行风险评估生成，请审批后替换模板名"))
}
