package monitor_test

import (
	"context"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/monitor"
	"os"
	"path/filepath"
	"testing"
)

func TestStateAndWebhookValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	r := finding.New("security", nil)
	if e := monitor.Save(p, r); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(p)
	if e != nil || st.Mode().Perm()&0077 != 0 {
		t.Fatal("state permissions", e)
	}
	if e := monitor.Notify(context.Background(), "http://example.test", r); e == nil {
		t.Fatal("unencrypted webhook accepted")
	}
}

func TestMissingScopesDoNotResolveRisks(t *testing.T) {
	old := finding.New("security", []finding.Finding{{ID: "cspm:risk", Subject: "cloud", Title: "risk", Severity: finding.SeverityHigh}})
	r := monitor.Merge(old, finding.New("security", nil))
	if len(r.Findings) != 1 {
		t.Fatal("unobserved risk removed")
	}
}
