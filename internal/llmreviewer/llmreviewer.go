// Package llmreviewer 封装基于 OpenAI Chat Completions 的审批 reviewer。
//
// 本包只负责把不含 secret 的 approval.Request 发送给 LLM，并解析结构化审批结果。
// reviewer 失败、返回格式错误或拒答时，调用方应视为 fail-closed，不执行生产动作。
package llmreviewer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RailyW/safe-inspector/internal/approval"
	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/risk"
)

const reviewerName = config.LLMProviderOpenAIChatCompletions

// Client 是 OpenAI Chat Completions reviewer 的客户端。
//
// HTTPClient 可在测试中注入；生产环境使用带超时的默认客户端。
type Client struct {
	Config     config.LLMApprovalConfig
	HTTPClient *http.Client
}

// New 根据配置创建 reviewer 客户端。
func New(cfg config.LLMApprovalConfig) *Client {
	cfg = normalizeConfig(cfg)
	return &Client{
		Config: cfg,
		HTTPClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
	}
}

// Review 调用 Chat Completions 并返回审批结果。
//
// 该方法不会修改 request.Command 或 request.SQL；LLM 只输出 allow/deny 与原因。
// 一旦 API key 缺失、HTTP 失败、模型拒答或 JSON 不符合预期，就返回错误交给 CLI
// 生成 fail-closed 的 deny 响应。
func (c *Client) Review(ctx context.Context, request approval.Request) (approval.Result, error) {
	cfg := normalizeConfig(c.Config)
	apiKey := strings.TrimSpace(os.Getenv(cfg.APIKeyEnv))
	if apiKey == "" {
		return approval.Result{}, fmt.Errorf("缺少 LLM 审批 API key 环境变量 %s", cfg.APIKeyEnv)
	}
	payload, err := buildChatRequest(cfg.Model, request)
	if err != nil {
		return approval.Result{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return approval.Result{}, fmt.Errorf("编码 LLM 审批请求失败: %w", err)
	}

	var lastErr error
	attempts := cfg.MaxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		result, err := c.callOnce(ctx, cfg, apiKey, body)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return approval.Result{}, lastErr
}

// callOnce 执行一次 Chat Completions HTTP 请求。
//
// 调用方负责重试；本函数只处理单次请求的鉴权头、状态码和响应体解析。
func (c *Client) callOnce(ctx context.Context, cfg config.LLMApprovalConfig, apiKey string, body []byte) (approval.Result, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second}
	}
	endpoint := chatCompletionsEndpoint(cfg.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return approval.Result{}, fmt.Errorf("创建 LLM 审批请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return approval.Result{}, fmt.Errorf("调用 LLM 审批失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return approval.Result{}, fmt.Errorf("读取 LLM 审批响应失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return approval.Result{}, fmt.Errorf("LLM 审批返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return parseChatResponse(cfg, respBody)
}

// buildChatRequest 构造 Chat Completions 请求体。
//
// developer 消息固定描述审批边界，user 消息只包含不带 secret 的 approval.Request。
func buildChatRequest(model string, request approval.Request) (map[string]any, error) {
	requestJSON, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("编码审批上下文失败: %w", err)
	}
	return map[string]any{
		"model": model,
		"messages": []map[string]string{
			{
				"role":    "developer",
				"content": "你是 safe-inspector 的生产环境操作审批 reviewer。只能根据用户提供的不含认证信息的 SSH/SQL 请求判断是否允许执行。不要改写命令或 SQL；如果证据不足、格式不明、可能造成破坏、权限变更、数据丢失或外传，返回 deny。必须严格按 JSON Schema 输出。",
			},
			{
				"role":    "user",
				"content": string(requestJSON),
			},
		},
		"response_format":       approvalSchema(),
		"max_completion_tokens": 300,
	}, nil
}

// approvalSchema 返回 Chat Completions structured output 使用的 JSON Schema。
//
// schema 只允许 allow/deny，不允许模型输出“改写后的命令”之类的执行内容。
func approvalSchema() map[string]any {
	return map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   "safe_inspector_approval",
			"strict": true,
			"schema": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"decision", "risk_level", "reason", "policy_violations", "confidence"},
				"properties": map[string]any{
					"decision": map[string]any{
						"type": "string",
						"enum": []string{"allow", "deny"},
					},
					"risk_level": map[string]any{
						"type": "string",
						"enum": []string{"low", "medium", "high", "critical"},
					},
					"reason": map[string]any{
						"type": "string",
					},
					"policy_violations": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"confidence": map[string]any{
						"type": "string",
						"enum": []string{"low", "medium", "high"},
					},
				},
			},
		},
	}
}

type chatResponse struct {
	ID      string       `json:"id"`
	Choices []chatChoice `json:"choices"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatMessage struct {
	Content string `json:"content"`
	Refusal string `json:"refusal,omitempty"`
}

type structuredDecision struct {
	Decision         string   `json:"decision"`
	RiskLevel        string   `json:"risk_level"`
	Reason           string   `json:"reason"`
	PolicyViolations []string `json:"policy_violations"`
	Confidence       string   `json:"confidence"`
}

// parseChatResponse 解析 Chat Completions 响应中的第一条 structured output。
//
// 模型拒答、空 choices 或 content 不是合法 JSON 都会返回错误，交给 CLI fail-closed。
func parseChatResponse(cfg config.LLMApprovalConfig, body []byte) (approval.Result, error) {
	var response chatResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return approval.Result{}, fmt.Errorf("解析 LLM 审批响应失败: %w", err)
	}
	if len(response.Choices) == 0 {
		return approval.Result{}, fmt.Errorf("LLM 审批响应没有 choices")
	}
	message := response.Choices[0].Message
	if strings.TrimSpace(message.Refusal) != "" {
		return approval.Result{}, fmt.Errorf("LLM 审批拒答: %s", message.Refusal)
	}
	var decision structuredDecision
	if err := json.Unmarshal([]byte(message.Content), &decision); err != nil {
		return approval.Result{}, fmt.Errorf("解析 LLM 审批结构化内容失败: %w", err)
	}
	result, err := decision.toApprovalResult(cfg, response.ID)
	if err != nil {
		return approval.Result{}, err
	}
	return result, nil
}

// toApprovalResult 将模型返回的结构化 JSON 转换为内部审批结果。
//
// 这里会二次校验枚举值，防止 reviewer 或兼容模型返回 schema 外内容。
func (d structuredDecision) toApprovalResult(cfg config.LLMApprovalConfig, requestID string) (approval.Result, error) {
	decision := risk.Decision(d.Decision)
	if decision != risk.DecisionAllow && decision != risk.DecisionDeny {
		return approval.Result{}, fmt.Errorf("LLM 审批返回未知 decision: %s", d.Decision)
	}
	level := risk.Level(d.RiskLevel)
	switch level {
	case risk.LevelLow, risk.LevelMedium, risk.LevelHigh, risk.LevelCritical:
	default:
		return approval.Result{}, fmt.Errorf("LLM 审批返回未知 risk_level: %s", d.RiskLevel)
	}
	reasons := []string{}
	if strings.TrimSpace(d.Reason) != "" {
		reasons = append(reasons, d.Reason)
	}
	reasons = append(reasons, d.PolicyViolations...)
	return approval.Result{
		Mode:             config.ApprovalModeLLM,
		Reviewer:         reviewerName,
		Decision:         decision,
		RiskLevel:        level,
		RiskReasons:      reasons,
		Reason:           d.Reason,
		PolicyViolations: d.PolicyViolations,
		Confidence:       d.Confidence,
		LLMModel:         cfg.Model,
		LLMRequestID:     requestID,
	}, nil
}

// normalizeConfig 补齐 reviewer 运行所需的默认配置。
//
// FailClosed 始终强制为 true；即使配置中写 false，也不允许 reviewer 失败时放行。
func normalizeConfig(cfg config.LLMApprovalConfig) config.LLMApprovalConfig {
	if cfg.Provider == "" {
		cfg.Provider = config.LLMProviderOpenAIChatCompletions
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = config.DefaultLLMBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = config.DefaultLLMModel
	}
	if cfg.APIKeyEnv == "" {
		cfg.APIKeyEnv = config.DefaultLLMAPIKeyEnv
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = config.DefaultLLMTimeoutSeconds
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = config.DefaultLLMMaxRetries
	}
	cfg.FailClosed = true
	return cfg
}

// chatCompletionsEndpoint 把 base URL 拼成 Chat Completions endpoint。
//
// 用户可以配置带 /v1 或不带 /v1 的 base URL；这里统一生成最终路径。
func chatCompletionsEndpoint(baseURL string) string {
	trimmed := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(trimmed, "/v1") {
		return trimmed + "/chat/completions"
	}
	return trimmed + "/v1/chat/completions"
}
