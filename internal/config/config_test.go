package config

import (
	"os"
	"testing"
)

func TestStoreInitCreatesConfigSecretsAndAuditFiles(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Init("master-key"); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	for _, path := range []string{store.Paths.ConfigFile, store.Paths.SecretsFile, store.Paths.AuditFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected file %s to exist: %v", path, err)
		}
	}

	cfg, err := store.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("config version mismatch: %d", cfg.Version)
	}
	if len(cfg.SSHTargets) != 0 || len(cfg.DBTargets) != 0 {
		t.Fatalf("new config should not contain targets: %#v", cfg)
	}
	if !cfg.MasterKey.Verify("master-key") {
		t.Fatalf("stored master key verifier rejected the original key")
	}

	secrets, err := store.LoadSecrets("master-key")
	if err != nil {
		t.Fatalf("LoadSecrets returned error with correct master key: %v", err)
	}
	if len(secrets.SSH) != 0 || len(secrets.DB) != 0 {
		t.Fatalf("new secrets should be empty: %#v", secrets)
	}
}

func TestStoreLoadSecretsRejectsWrongMasterKey(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Init("master-key"); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	if _, err := store.LoadSecrets("wrong-key"); err == nil {
		t.Fatalf("LoadSecrets accepted a wrong master key")
	}
}

func TestAdhocPolicyDefaultsToDisabledForOldTargets(t *testing.T) {
	sshTarget := SSHTarget{ID: "prod-ssh"}
	if sshTarget.AdhocPolicy.Enabled {
		t.Fatalf("zero-value SSH adhoc policy must be disabled")
	}
	if sshTarget.NormalizedAdhocPolicy().Enabled {
		t.Fatalf("normalized zero-value SSH adhoc policy must stay disabled")
	}

	dbTarget := DBTarget{ID: "prod-db"}
	if dbTarget.AdhocPolicy.Enabled {
		t.Fatalf("zero-value DB adhoc policy must be disabled")
	}
	if dbTarget.NormalizedAdhocPolicy().Enabled {
		t.Fatalf("normalized zero-value DB adhoc policy must stay disabled")
	}
}

func TestApprovalDefaultsToClassicForOldConfigs(t *testing.T) {
	cfg := Config{}
	approval := cfg.NormalizedApproval()
	if approval.Mode != ApprovalModeClassic {
		t.Fatalf("zero-value approval mode = %q, want %q", approval.Mode, ApprovalModeClassic)
	}
	if approval.LLM.Provider != LLMProviderOpenAIChatCompletions {
		t.Fatalf("default llm provider = %q, want %q", approval.LLM.Provider, LLMProviderOpenAIChatCompletions)
	}
	if approval.LLM.Model != DefaultLLMModel {
		t.Fatalf("default llm model = %q, want %q", approval.LLM.Model, DefaultLLMModel)
	}
	if approval.LLM.APIKeyEnv != DefaultLLMAPIKeyEnv {
		t.Fatalf("default llm api key env = %q, want %q", approval.LLM.APIKeyEnv, DefaultLLMAPIKeyEnv)
	}
	if !approval.LLM.FailClosed {
		t.Fatalf("llm approval must default to fail-closed")
	}
}

func TestStoreInitPersistsClassicApprovalMode(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if err := store.Init("master-key"); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if got := cfg.NormalizedApproval().Mode; got != ApprovalModeClassic {
		t.Fatalf("initialized approval mode = %q, want %q", got, ApprovalModeClassic)
	}
}
