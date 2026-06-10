package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/dbclient"
	"github.com/RailyW/safe-inspector/internal/secure"
	"github.com/RailyW/safe-inspector/internal/sshclient"
)

func TestRunPrintsSkillsForLanguageModel(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--skills"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("Run returned exit code %d, stderr: %s", exitCode, stderr.String())
	}

	output := stdout.String()
	for _, expected := range []string{"safe-inspector", "安全模板", "不要输出密码", "ssh template add", "db template add"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("--skills output did not contain %q\noutput:\n%s", expected, output)
		}
	}
}

func TestRunStatusReportsMissingEnvironmentKeyAsJSON(t *testing.T) {
	t.Setenv("SAFE_INSPECTOR_MASTER_KEY", "")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--config-dir", t.TempDir(), "status"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("status should return success for diagnostics, got %d stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"env_master_key":false`) {
		t.Fatalf("status JSON did not report missing env key: %s", stdout.String())
	}
}

func TestRunSSHRiskReturnsTemplateSuggestionForMediumCommand(t *testing.T) {
	store := initTestStoreWithConfig(t, func(cfg *config.Config) {
		cfg.SSHTargets = append(cfg.SSHTargets, config.SSHTarget{ID: "prod-ssh", Host: "127.0.0.1", Port: 22, User: "root", AuthType: "password"})
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--config-dir", store.Paths.Dir, "ssh", "risk", "--target", "prod-ssh", "--command", "cat /var/log/app.log"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("ssh risk should return success diagnostics, got %d stderr=%s", exitCode, stderr.String())
	}
	assertJSONField(t, stdout.String(), "decision", "template_required")
	if !strings.Contains(stdout.String(), "suggested_approval_command") {
		t.Fatalf("ssh risk did not include template suggestion: %s", stdout.String())
	}
}

func TestRunSSHRunRejectsDisabledAdhocPolicy(t *testing.T) {
	store := initTestStoreWithConfig(t, func(cfg *config.Config) {
		cfg.SSHTargets = append(cfg.SSHTargets, config.SSHTarget{ID: "prod-ssh", Host: "127.0.0.1", Port: 22, User: "root", AuthType: "password"})
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--config-dir", store.Paths.Dir, "ssh", "run", "--target", "prod-ssh", "--command", "date"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode == 0 {
		t.Fatalf("ssh run should reject disabled adhoc policy")
	}
	assertJSONField(t, stdout.String(), "decision", "deny")
	if !strings.Contains(stdout.String(), "adhoc") {
		t.Fatalf("ssh run denial should mention adhoc policy: %s", stdout.String())
	}
}

func TestRunSSHRunExecutesLowRiskCommandWhenAdhocEnabled(t *testing.T) {
	store := initTestStoreWithConfig(t, func(cfg *config.Config) {
		cfg.SSHTargets = append(cfg.SSHTargets, config.SSHTarget{
			ID:       "prod-ssh",
			Host:     "127.0.0.1",
			Port:     22,
			User:     "root",
			AuthType: "password",
			AdhocPolicy: config.AdhocPolicy{Enabled: true, MaxRisk: "low",
				Profile: "observability-v1"},
		})
	})
	if err := store.SaveSecrets("master-key", config.Secrets{SSH: map[string]config.SSHSecret{"prod-ssh": {Password: "secret"}}, DB: map[string]config.DBSecret{}}); err != nil {
		t.Fatalf("SaveSecrets returned error: %v", err)
	}
	t.Setenv(secure.EnvMasterKey, "master-key")
	oldSSHExecute := sshExecute
	t.Cleanup(func() { sshExecute = oldSSHExecute })
	sshExecute = func(ctx context.Context, target config.SSHTarget, secret config.SSHSecret, command string, useSudo bool, timeout time.Duration, maxOutputBytes int64) (sshclient.Result, error) {
		if command != "date" || useSudo {
			t.Fatalf("unexpected SSH execution command=%q sudo=%v", command, useSudo)
		}
		return sshclient.Result{Stdout: "Wed Jun 10\n", ExitCode: 0}, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--config-dir", store.Paths.Dir, "ssh", "run", "--target", "prod-ssh", "--command", "date"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("ssh run should execute low-risk command, got %d stderr=%s stdout=%s", exitCode, stderr.String(), stdout.String())
	}
	assertJSONField(t, stdout.String(), "risk_level", "low")
	assertJSONField(t, stdout.String(), "decision", "allow")
	if !strings.Contains(stdout.String(), "Wed Jun 10") {
		t.Fatalf("ssh run did not include fake stdout: %s", stdout.String())
	}
}

func TestRunDBQueryReturnsTemplateSuggestionForWriteSQL(t *testing.T) {
	store := initTestStoreWithConfig(t, func(cfg *config.Config) {
		cfg.DBTargets = append(cfg.DBTargets, config.DBTarget{ID: "prod-db", Driver: "mysql", Host: "127.0.0.1", Port: 3306, Database: "app", Username: "reader"})
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--config-dir", store.Paths.Dir, "db", "query", "--target", "prod-db", "--sql", "update users set name = 'a' where id = 1"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("db query should return template diagnostics for write SQL, got %d stderr=%s", exitCode, stderr.String())
	}
	assertJSONField(t, stdout.String(), "decision", "template_required")
	if !strings.Contains(stdout.String(), "db template add") {
		t.Fatalf("db query did not include approval command: %s", stdout.String())
	}
}

func TestRunDBQueryExecutesLowRiskSQLWhenAdhocEnabled(t *testing.T) {
	store := initTestStoreWithConfig(t, func(cfg *config.Config) {
		cfg.DBTargets = append(cfg.DBTargets, config.DBTarget{
			ID:       "prod-db",
			Driver:   "mysql",
			Host:     "127.0.0.1",
			Port:     3306,
			Database: "app",
			Username: "reader",
			AdhocPolicy: config.AdhocPolicy{Enabled: true, MaxRisk: "low",
				Profile: "readonly-v1"},
		})
	})
	if err := store.SaveSecrets("master-key", config.Secrets{SSH: map[string]config.SSHSecret{}, DB: map[string]config.DBSecret{"prod-db": {Password: "secret"}}}); err != nil {
		t.Fatalf("SaveSecrets returned error: %v", err)
	}
	t.Setenv(secure.EnvMasterKey, "master-key")
	oldDBExecute := dbExecute
	t.Cleanup(func() { dbExecute = oldDBExecute })
	dbExecute = func(ctx context.Context, target config.DBTarget, secret config.DBSecret, query string, args []any, kind string, timeout time.Duration, maxOutputBytes int64) (dbclient.Result, error) {
		if query != "select 1" || kind != "read" {
			t.Fatalf("unexpected DB execution query=%q kind=%q", query, kind)
		}
		return dbclient.Result{Columns: []string{"1"}, Rows: []map[string]any{{"1": int64(1)}}}, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--config-dir", store.Paths.Dir, "db", "query", "--target", "prod-db", "--sql", "select 1"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("db query should execute low-risk SQL, got %d stderr=%s stdout=%s", exitCode, stderr.String(), stdout.String())
	}
	assertJSONField(t, stdout.String(), "risk_level", "low")
	assertJSONField(t, stdout.String(), "decision", "allow")
	if !strings.Contains(stdout.String(), `"columns":["1"]`) {
		t.Fatalf("db query did not include fake result: %s", stdout.String())
	}
}

func initTestStoreWithConfig(t *testing.T, mutate func(*config.Config)) config.Store {
	t.Helper()
	store, err := config.NewStore(t.TempDir())
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
	mutate(&cfg)
	if err := store.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig returned error: %v", err)
	}
	return store
}

func assertJSONField(t *testing.T, raw string, key string, expected any) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, raw)
	}
	if payload[key] != expected {
		t.Fatalf("JSON field %s = %#v, want %#v\npayload=%#v", key, payload[key], expected, payload)
	}
}
