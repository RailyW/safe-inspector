package llmreviewer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RailyW/safe-inspector/internal/approval"
	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/risk"
)

func TestReviewParsesStructuredAllowResponse(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	var sawSchema bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body["model"] != "gpt-test" {
			t.Fatalf("model = %#v, want gpt-test", body["model"])
		}
		if responseFormat, ok := body["response_format"].(map[string]any); ok && responseFormat["type"] == "json_schema" {
			sawSchema = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-test",
			"choices":[{"message":{"content":"{\"decision\":\"allow\",\"risk_level\":\"medium\",\"reason\":\"诊断读取可接受\",\"policy_violations\":[],\"confidence\":\"high\"}"}}]
		}`))
	}))
	defer server.Close()

	reviewer := New(config.LLMApprovalConfig{
		Provider:       config.LLMProviderOpenAIChatCompletions,
		BaseURL:        server.URL,
		Model:          "gpt-test",
		APIKeyEnv:      "OPENAI_API_KEY",
		TimeoutSeconds: 2,
		MaxRetries:     0,
		FailClosed:     true,
	})
	result, err := reviewer.Review(context.Background(), approval.Request{
		Operation: "ssh.run",
		TargetID:  "prod-ssh",
		Command:   "cat /var/log/app.log",
		ClassicRisk: risk.Assessment{
			Level:    risk.LevelMedium,
			Decision: risk.DecisionTemplateRequired,
			Reasons:  []string{"classic requires template"},
		},
	})
	if err != nil {
		t.Fatalf("Review returned error: %v", err)
	}
	if !sawSchema {
		t.Fatalf("review request did not use Chat Completions structured output schema")
	}
	if result.Decision != risk.DecisionAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
	if result.RiskLevel != risk.LevelMedium {
		t.Fatalf("risk level = %q, want medium", result.RiskLevel)
	}
	if result.LLMRequestID != "chatcmpl-test" {
		t.Fatalf("request id = %q, want chatcmpl-test", result.LLMRequestID)
	}
	if result.LLMModel != "gpt-test" {
		t.Fatalf("model = %q, want gpt-test", result.LLMModel)
	}
}

func TestReviewFailsClosedWhenAPIKeyMissing(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	reviewer := New(config.LLMApprovalConfig{
		Provider:       config.LLMProviderOpenAIChatCompletions,
		BaseURL:        "http://127.0.0.1:1",
		Model:          "gpt-test",
		APIKeyEnv:      "OPENAI_API_KEY",
		TimeoutSeconds: 1,
		FailClosed:     true,
	})
	_, err := reviewer.Review(context.Background(), approval.Request{Operation: "db.query", SQL: "select 1"})
	if err == nil {
		t.Fatalf("Review should fail closed when API key env is missing")
	}
	if !strings.Contains(err.Error(), "OPENAI_API_KEY") {
		t.Fatalf("error should mention missing API key env, got: %v", err)
	}
}

func TestChatCompletionsEndpointAcceptsVersionedBaseURL(t *testing.T) {
	tests := map[string]string{
		"https://api.openai.com":    "https://api.openai.com/v1/chat/completions",
		"https://api.openai.com/v1": "https://api.openai.com/v1/chat/completions",
	}
	for baseURL, want := range tests {
		if got := chatCompletionsEndpoint(baseURL); got != want {
			t.Fatalf("chatCompletionsEndpoint(%q) = %q, want %q", baseURL, got, want)
		}
	}
}
