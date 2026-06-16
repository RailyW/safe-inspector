package approval

import (
	"context"
	"testing"

	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/risk"
)

func TestDangerApproverAllowsAndMarksBypassed(t *testing.T) {
	result, err := DangerApprover{}.Review(context.Background(), Request{
		Operation: "ssh.run",
		TargetID:  "prod-ssh",
		Command:   "rm -rf /tmp/example",
		ClassicRisk: risk.Assessment{
			Level:    risk.LevelCritical,
			Decision: risk.DecisionDeny,
			Reasons:  []string{"classic would deny"},
		},
	})
	if err != nil {
		t.Fatalf("DangerApprover returned error: %v", err)
	}
	if result.Mode != config.ApprovalModeDangerAllowAll {
		t.Fatalf("mode = %q, want %q", result.Mode, config.ApprovalModeDangerAllowAll)
	}
	if result.Decision != risk.DecisionAllow {
		t.Fatalf("decision = %q, want %q", result.Decision, risk.DecisionAllow)
	}
	if !result.ApprovalBypassed {
		t.Fatalf("danger approval must mark approval_bypassed=true")
	}
}
