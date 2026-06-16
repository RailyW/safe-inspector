package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RailyW/safe-inspector/internal/approval"
	"github.com/RailyW/safe-inspector/internal/audit"
	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/llmreviewer"
	"github.com/RailyW/safe-inspector/internal/risk"
)

// llmReviewerFactory 是 LLM reviewer 的注入点。
//
// 生产环境创建 OpenAI Chat Completions reviewer；测试可以替换该函数，避免真实网络。
var llmReviewerFactory = func(cfg config.LLMApprovalConfig) approval.Approver {
	return llmreviewer.New(cfg)
}

// runApproval 分发审批模式相关命令。
//
// 这里不直接执行 SSH/SQL，只负责查看或修改全局审批配置，以及测试 LLM reviewer。
func runApproval(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "approval 缺少子命令：status、mode set、llm test")
		return 2
	}
	switch args[0] {
	case "status":
		return runApprovalStatus(store, opts, stdout, stderr)
	case "mode":
		if len(args) >= 2 && args[1] == "set" {
			return runApprovalModeSet(store, opts, args[2:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "approval mode 仅支持 set")
		return 2
	case "llm":
		if len(args) >= 2 && args[1] == "test" {
			return runApprovalLLMTest(store, opts, stdout, stderr)
		}
		fmt.Fprintln(stderr, "approval llm 仅支持 test")
		return 2
	default:
		fmt.Fprintf(stderr, "未知 approval 子命令: %s\n", args[0])
		return 2
	}
}

// runApprovalStatus 输出当前审批模式和 LLM reviewer 的非敏感配置。
//
// API key 只报告环境变量是否存在，不输出环境变量值。
func runApprovalStatus(store config.Store, opts globalOptions, stdout io.Writer, stderr io.Writer) int {
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	approvalCfg := cfg.NormalizedApproval()
	response := map[string]any{
		"ok":                  true,
		"mode":                approvalCfg.Mode,
		"llm_provider":        approvalCfg.LLM.Provider,
		"llm_base_url":        approvalCfg.LLM.BaseURL,
		"llm_model":           approvalCfg.LLM.Model,
		"llm_api_key_env":     approvalCfg.LLM.APIKeyEnv,
		"llm_api_key_present": os.Getenv(approvalCfg.LLM.APIKeyEnv) != "",
		"llm_timeout_seconds": approvalCfg.LLM.TimeoutSeconds,
		"llm_max_retries":     approvalCfg.LLM.MaxRetries,
		"llm_fail_closed":     approvalCfg.LLM.FailClosed,
	}
	return writeValue(stdout, opts.Format, response)
}

// runApprovalModeSet 修改全局审批模式。
//
// 审批模式会改变生产执行边界，因此必须复用策略变更流程：用户在 TTY 输入主秘钥。
// dangerous 模式还要求显式确认参数，避免误操作。
func runApprovalModeSet(store config.Store, opts globalOptions, args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("approval mode set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "", "审批模式：classic、llm、danger_allow_all")
	provider := fs.String("provider", config.LLMProviderOpenAIChatCompletions, "LLM provider，当前仅支持 openai_chat_completions")
	baseURL := fs.String("base-url", config.DefaultLLMBaseURL, "LLM API base URL")
	model := fs.String("model", config.DefaultLLMModel, "LLM 模型")
	apiKeyEnv := fs.String("api-key-env", config.DefaultLLMAPIKeyEnv, "保存 API key 的环境变量名")
	timeoutSeconds := fs.Int("timeout", config.DefaultLLMTimeoutSeconds, "LLM 审批超时秒数")
	maxRetries := fs.Int("max-retries", config.DefaultLLMMaxRetries, "LLM 审批最大重试次数")
	understandRisk := fs.Bool("i-understand-production-risk", false, "确认开启危险放行模式")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, _, err := loadConfigAndVerifyMaster(store, stdout)
	if err != nil {
		return writeError(stderr, err)
	}
	switch *mode {
	case config.ApprovalModeClassic:
		cfg.Approval = config.DefaultApprovalConfig()
	case config.ApprovalModeLLM:
		if *provider != config.LLMProviderOpenAIChatCompletions {
			return writeError(stderr, fmt.Errorf("当前仅支持 LLM provider %s", config.LLMProviderOpenAIChatCompletions))
		}
		cfg.Approval = config.ApprovalConfig{
			Mode: config.ApprovalModeLLM,
			LLM: config.LLMApprovalConfig{
				Provider:       *provider,
				BaseURL:        *baseURL,
				Model:          *model,
				APIKeyEnv:      *apiKeyEnv,
				TimeoutSeconds: *timeoutSeconds,
				MaxRetries:     *maxRetries,
				FailClosed:     true,
			},
		}
	case config.ApprovalModeDangerAllowAll:
		if !*understandRisk {
			return writeError(stderr, fmt.Errorf("开启 danger_allow_all 必须显式传入 --i-understand-production-risk"))
		}
		cfg.Approval = config.ApprovalConfig{
			Mode: config.ApprovalModeDangerAllowAll,
			LLM:  config.DefaultApprovalConfig().LLM,
		}
	default:
		return writeError(stderr, fmt.Errorf("--mode 只支持 classic、llm、danger_allow_all"))
	}
	if err := store.SaveConfig(cfg); err != nil {
		return writeError(stderr, err)
	}
	normalized := cfg.NormalizedApproval()
	auditID := writeAudit(store, audit.Event{Action: "approval.mode.set", OK: true, ApprovalMode: normalized.Mode})
	return writeValue(stdout, opts.Format, map[string]any{"ok": true, "mode": normalized.Mode, "audit_id": auditID})
}

// runApprovalLLMTest 发送一次无生产目标的 LLM 审批自检请求。
//
// 该命令不读取 safe-inspector secret，也不连接 SSH/MySQL；它只验证 API key、
// HTTP 连接和 structured output 解析是否可用。
func runApprovalLLMTest(store config.Store, opts globalOptions, stdout io.Writer, stderr io.Writer) int {
	cfg, err := store.LoadConfig()
	if err != nil {
		return writeError(stderr, err)
	}
	approvalCfg := cfg.NormalizedApproval()
	result, reviewErr := llmReviewerFactory(approvalCfg.LLM).Review(context.Background(), approval.Request{
		Operation: "approval.llm.test",
		TargetID:  "__self_test__",
		ClassicRisk: risk.Assessment{
			Level:    risk.LevelLow,
			Decision: risk.DecisionAllow,
			Reasons:  []string{"LLM 审批连通性自检"},
		},
	})
	response := map[string]any{"ok": reviewErr == nil}
	if reviewErr != nil {
		result = approval.DeniedResult(config.ApprovalModeLLM, config.LLMProviderOpenAIChatCompletions, resultToAssessment(result), reviewErr.Error())
		response["error"] = reviewErr.Error()
	}
	addApprovalFields(response, result)
	writeValue(stdout, opts.Format, response)
	if reviewErr != nil {
		return 1
	}
	return 0
}

// reviewExecution 根据全局 approval 配置选择 classic、LLM 或 danger 审批器。
//
// LLM reviewer 出错时不会向外抛出命令级异常，而是返回 fail-closed 的 deny 结果；
// 这样执行命令仍能用稳定 JSON 告诉 agent “没有执行”。
func reviewExecution(ctx context.Context, cfg config.Config, request approval.Request) (approval.Result, error) {
	approvalCfg := cfg.NormalizedApproval()
	switch approvalCfg.Mode {
	case config.ApprovalModeClassic:
		return approval.ClassicApprover{}.Review(ctx, request)
	case config.ApprovalModeDangerAllowAll:
		return approval.DangerApprover{}.Review(ctx, request)
	case config.ApprovalModeLLM:
		if approvalCfg.LLM.Provider != config.LLMProviderOpenAIChatCompletions {
			result := approval.DeniedResult(config.ApprovalModeLLM, approvalCfg.LLM.Provider, request.ClassicRisk, "未知 LLM 审批 provider")
			return result, fmt.Errorf("未知 LLM 审批 provider: %s", approvalCfg.LLM.Provider)
		}
		result, err := llmReviewerFactory(approvalCfg.LLM).Review(ctx, request)
		if err != nil {
			return approval.DeniedResult(config.ApprovalModeLLM, config.LLMProviderOpenAIChatCompletions, request.ClassicRisk, err.Error()), err
		}
		return result, nil
	default:
		return approval.DeniedResult(approvalCfg.Mode, "unknown", request.ClassicRisk, "未知审批模式"), fmt.Errorf("未知审批模式: %s", approvalCfg.Mode)
	}
}

// addApprovalFields 把审批结果写入 CLI JSON 响应。
func addApprovalFields(response map[string]any, result approval.Result) {
	response["approval_mode"] = result.Mode
	response["reviewer"] = result.Reviewer
	response["decision"] = string(result.Decision)
	response["risk_level"] = string(result.RiskLevel)
	response["risk_reasons"] = result.RiskReasons
	if result.Reason != "" {
		response["approval_reason"] = result.Reason
	}
	if len(result.PolicyViolations) > 0 {
		response["policy_violations"] = result.PolicyViolations
	}
	if result.Confidence != "" {
		response["llm_confidence"] = result.Confidence
	}
	if result.LLMModel != "" {
		response["llm_model"] = result.LLMModel
	}
	if result.LLMRequestID != "" {
		response["llm_request_id"] = result.LLMRequestID
	}
	if result.ApprovalBypassed {
		response["approval_bypassed"] = true
	}
	if result.SuggestedTemplate != "" {
		response["suggested_approval_command"] = result.SuggestedTemplate
	}
}

// approvalAuditFields 将审批结果复制到审计事件中。
//
// 这样 CLI 输出和 audit.jsonl 可以用同一组字段关联审批模式、reviewer 和 LLM request id。
func approvalAuditFields(event audit.Event, result approval.Result) audit.Event {
	event.RiskLevel = string(result.RiskLevel)
	event.Decision = string(result.Decision)
	event.RiskReasons = result.RiskReasons
	event.ApprovalMode = result.Mode
	event.Reviewer = result.Reviewer
	event.LLMModel = result.LLMModel
	event.LLMRequestID = result.LLMRequestID
	event.ApprovalBypassed = result.ApprovalBypassed
	return event
}

// resultToAssessment 把审批结果降级成风险评估结构。
//
// 它主要用于 reviewer 出错后构造 fail-closed 结果。
func resultToAssessment(result approval.Result) risk.Assessment {
	return risk.Assessment{Level: result.RiskLevel, Decision: result.Decision, Reasons: result.RiskReasons}
}

// classicApprovalResult 把确定性风险评估包装成 classic 审批结果。
func classicApprovalResult(assessment risk.Assessment) approval.Result {
	return approval.Result{
		Mode:        config.ApprovalModeClassic,
		Reviewer:    approval.ReviewerClassic,
		Decision:    assessment.Decision,
		RiskLevel:   assessment.Level,
		RiskReasons: assessment.Reasons,
	}
}
