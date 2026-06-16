// Package approval 定义 safe-inspector 的执行审批抽象。
//
// 本包不连接 SSH、数据库或 LLM，只定义审批请求、审批结果和内置审批器。
// CLI 会先构造不含 secret 的 Request，再交给 classic、LLM 或 danger 审批器决定是否执行。
package approval

import (
	"context"

	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/risk"
)

const (
	OperationSSHExec = "ssh.exec"
	OperationSSHRun  = "ssh.run"
	OperationDBExec  = "db.exec"
	OperationDBQuery = "db.query"

	ReviewerClassic = "classic"
	ReviewerDanger  = "danger_allow_all"
)

// Request 是一次待执行动作的审批输入。
//
// 该结构严禁包含密码、sudo 密码、主秘钥、SSH 私钥 passphrase 等 AUTH 信息。
// Command/SQL 可以包含业务文本，因此审计时仍应只记录摘要；但发送给 LLM 审批器时
// 需要保留原文，否则 reviewer 无法判断动作风险。
type Request struct {
	Operation    string            `json:"operation"`
	TargetID     string            `json:"target_id"`
	TemplateName string            `json:"template_name,omitempty"`
	Command      string            `json:"command,omitempty"`
	SQL          string            `json:"sql,omitempty"`
	SQLKind      string            `json:"sql_kind,omitempty"`
	Sudo         bool              `json:"sudo,omitempty"`
	Params       map[string]string `json:"params,omitempty"`
	ClassicRisk  risk.Assessment   `json:"classic_risk"`
}

// Result 是审批器返回给 CLI 的稳定结构。
//
// Decision 使用 risk.Decision，便于和现有 JSON 字段保持一致；LLM 相关字段只有
// LLM reviewer 会填充；危险模式必须设置 ApprovalBypassed=true。
type Result struct {
	Mode              string        `json:"approval_mode"`
	Reviewer          string        `json:"reviewer"`
	Decision          risk.Decision `json:"decision"`
	RiskLevel         risk.Level    `json:"risk_level"`
	RiskReasons       []string      `json:"risk_reasons,omitempty"`
	Reason            string        `json:"reason,omitempty"`
	PolicyViolations  []string      `json:"policy_violations,omitempty"`
	Confidence        string        `json:"confidence,omitempty"`
	LLMModel          string        `json:"llm_model,omitempty"`
	LLMRequestID      string        `json:"llm_request_id,omitempty"`
	ApprovalBypassed  bool          `json:"approval_bypassed,omitempty"`
	SuggestedTemplate string        `json:"suggested_approval_command,omitempty"`
}

// Approver 是所有审批模式共同实现的接口。
//
// Review 只能给出是否允许执行的决定，不允许修改 SSH 命令或 SQL 文本；调用方必须
// 执行原始请求中的 Command/SQL，避免 reviewer 悄悄扩大操作范围。
type Approver interface {
	Review(ctx context.Context, request Request) (Result, error)
}

// ClassicApprover 保持当前确定性审批模式。
//
// 模板执行由 CLI 在构造请求前完成模板存在性和参数校验，因此这里直接允许；
// 临时执行使用 Request.ClassicRisk 的确定性结果。
type ClassicApprover struct{}

// Review 返回 classic 模式下的审批结果。
func (ClassicApprover) Review(ctx context.Context, request Request) (Result, error) {
	assessment := request.ClassicRisk
	if assessment.Decision == "" {
		assessment = risk.Assessment{Level: risk.LevelLow, Decision: risk.DecisionAllow, Reasons: []string{"已批准模板执行"}}
	}
	return Result{
		Mode:        config.ApprovalModeClassic,
		Reviewer:    ReviewerClassic,
		Decision:    assessment.Decision,
		RiskLevel:   assessment.Level,
		RiskReasons: assessment.Reasons,
	}, nil
}

// DangerApprover 是危险的完全放行模式。
//
// 它忽略 classic 风险分级和 LLM reviewer，始终返回 allow。调用方必须在输出和审计
// 中保留 approval_bypassed=true，提醒用户本次没有经过安全审批。
type DangerApprover struct{}

// Review 返回危险模式下的放行结果。
func (DangerApprover) Review(ctx context.Context, request Request) (Result, error) {
	return Result{
		Mode:             config.ApprovalModeDangerAllowAll,
		Reviewer:         ReviewerDanger,
		Decision:         risk.DecisionAllow,
		RiskLevel:        request.ClassicRisk.Level,
		RiskReasons:      append([]string{"危险模式已启用：审批与风险校验被显式绕过"}, request.ClassicRisk.Reasons...),
		ApprovalBypassed: true,
	}, nil
}

// DeniedResult 构造审批失败或 reviewer fail-closed 的统一结果。
func DeniedResult(mode string, reviewer string, assessment risk.Assessment, reason string) Result {
	reasons := append([]string{}, assessment.Reasons...)
	if reason != "" {
		reasons = append(reasons, reason)
	}
	level := assessment.Level
	if level == "" {
		level = risk.LevelCritical
	}
	return Result{
		Mode:        mode,
		Reviewer:    reviewer,
		Decision:    risk.DecisionDeny,
		RiskLevel:   level,
		RiskReasons: reasons,
		Reason:      reason,
	}
}
