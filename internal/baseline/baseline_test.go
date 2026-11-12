package baseline_test

import (
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"testing"
)

func TestMovesEscalationsAndIncomplete(t *testing.T) {
	f := finding.Finding{ID: "sast:x", Subject: "a#f", Title: "x", Severity: finding.SeverityMedium, Location: &finding.Location{File: "a", Line: 1}}
	old := finding.New("security", []finding.Finding{f})
	f.Location = &finding.Location{File: "a", Line: 99}
	if len(baseline.New(old, finding.New("security", []finding.Finding{f})).Findings) != 0 {
		t.Fatal("line move is new")
	}
	f.Severity = finding.SeverityHigh
	if len(baseline.New(old, finding.New("security", []finding.Finding{f})).Findings) != 1 {
		t.Fatal("escalation hidden")
	}
	f.ID = "sast:analysis-incomplete"
	old = finding.New("security", []finding.Finding{f})
	if len(baseline.New(old, old).Findings) != 1 {
		t.Fatal("incompleteness hidden")
	}
}
