// Package audit 负责把配置变更和执行动作写入本地 JSONL 审计日志。
//
// 审计日志只记录目标、模板、参数摘要、风险等级、风险决策、结果状态和错误类别，
// 严禁写入任何 SSH/MySQL 密码、主秘钥、私钥 passphrase 或 sudo 密码。
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Event 是 audit.jsonl 中的一行审计记录。
type Event struct {
	ID               string            `json:"id"`
	Time             time.Time         `json:"time"`
	Action           string            `json:"action"`
	Target           string            `json:"target,omitempty"`
	Template         string            `json:"template,omitempty"`
	Params           map[string]string `json:"params,omitempty"`
	RiskLevel        string            `json:"risk_level,omitempty"`
	Decision         string            `json:"decision,omitempty"`
	RiskReasons      []string          `json:"risk_reasons,omitempty"`
	ApprovalMode     string            `json:"approval_mode,omitempty"`
	Reviewer         string            `json:"reviewer,omitempty"`
	LLMModel         string            `json:"llm_model,omitempty"`
	LLMRequestID     string            `json:"llm_request_id,omitempty"`
	ApprovalBypassed bool              `json:"approval_bypassed,omitempty"`
	OK               bool              `json:"ok"`
	DurationMS       int64             `json:"duration_ms,omitempty"`
	ErrorClass       string            `json:"error_class,omitempty"`
}

// Writer 将审计事件追加到 JSONL 文件。
type Writer struct {
	Path string
}

// Write 写入一条审计事件；如果 ID 或 Time 为空，会自动补齐。
func (w Writer) Write(event Event) (string, error) {
	if event.ID == "" {
		event.ID = NewID()
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if err := os.MkdirAll(parentDir(w.Path), 0o700); err != nil {
		return "", fmt.Errorf("创建审计目录失败: %w", err)
	}
	file, err := os.OpenFile(w.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("打开审计日志失败: %w", err)
	}
	defer file.Close()

	line, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("编码审计事件失败: %w", err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		return "", fmt.Errorf("写入审计日志失败: %w", err)
	}
	return event.ID, nil
}

// NewID 生成短随机审计 ID，用于把 CLI 输出和 audit.jsonl 关联起来。
func NewID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
