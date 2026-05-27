package cli

import (
	"bytes"
	"strings"
	"testing"
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
