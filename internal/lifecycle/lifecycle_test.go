package lifecycle_test

import (
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/lifecycle"
	"github.com/securock/securock/internal/runrecord"
	"testing"
)

func TestResolutionReopeningAndCoverage(t *testing.T) {
	f := finding.Finding{ID: "sast:x", Subject: "a#f", Title: "x", Severity: finding.SeverityHigh, Location: &finding.Location{File: "a.go", Line: 1}}
	r := runrecord.New("v1", "rev", "cfg", "app", false, []string{"a.go"}, finding.New("security", []finding.Finding{f}), true)
	state := lifecycle.Step(lifecycle.Registry{}, r)
	if state.Entries[0].State != "new" {
		t.Fatal(state)
	}
	clean := runrecord.New("v1", "rev2", "cfg", "app", false, []string{"a.go"}, finding.New("security", nil), true)
	resolved := lifecycle.Step(state, clean)
	if resolved.Entries[0].State != "resolved" {
		t.Fatal(resolved)
	}
	again := lifecycle.Step(resolved, r)
	if again.Entries[0].State != "reopened" {
		t.Fatal(again)
	}
	clean.Scopes[0].Complete = false
	if lifecycle.Step(state, clean).Entries[0].State != "unobserved" {
		t.Fatal("incomplete scan resolved finding")
	}
	clean.Files = nil
	clean.Scopes[0].Complete = true
	if lifecycle.Step(state, clean).Entries[0].State != "unobserved" {
		t.Fatal("missing file resolved finding")
	}
	if e := lifecycle.Assign(&state, state.Entries[0].Key, "team", "2030-01-01"); e != nil {
		t.Fatal(e)
	}
	lifecycle.Age(&state, "2030-01-02")
	if !state.Entries[0].Overdue {
		t.Fatal("deadline not tracked")
	}
}

func TestChangedConfigurationCannotLaunderResolution(t *testing.T) {
	f := finding.Finding{ID: "sast:x", Title: "risk", Severity: finding.SeverityHigh, Location: &finding.Location{File: "a.go", Line: 1}}
	observed := runrecord.New("v1", "a", "enabled", "app", false, []string{"a.go"}, finding.New("security", []finding.Finding{f}), true)
	state := lifecycle.Step(lifecycle.Registry{}, observed)
	disabled := runrecord.New("v1", "b", "disabled", "app", false, []string{"a.go"}, finding.New("security", nil), true)
	state = lifecycle.Step(state, disabled)
	disabled.Revision = "c"
	state = lifecycle.Step(state, disabled)
	if state.Entries[0].State != "unobserved" {
		t.Fatal("changed settings falsely resolved risk")
	}
	restored := runrecord.New("v1", "d", "enabled", "app", false, []string{"a.go"}, finding.New("security", nil), true)
	state = lifecycle.Step(state, restored)
	if state.Entries[0].State != "resolved" {
		t.Fatal(state)
	}
}
