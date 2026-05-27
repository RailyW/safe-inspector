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
