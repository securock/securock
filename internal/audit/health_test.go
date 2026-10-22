package audit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

func TestHealthFindings(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		eco    string
		pkg    string
		health *lockfile.HealthEvidence
		want   map[string]finding.Severity
	}{
		{"nothing to report", "npm", "left-pad", &lockfile.HealthEvidence{Released: "2026-01-01", License: "MIT"}, nil},
		{"not checked", "npm", "left-pad", nil, nil},
		{"deprecated", "npm", "left-pad", &lockfile.HealthEvidence{Deprecated: "use x"}, map[string]finding.Severity{"deprecated-package": finding.SeverityMedium}},
		{"yanked", "pypi", "sample", &lockfile.HealthEvidence{Deprecated: "yanked: broken"}, map[string]finding.Severity{"deprecated-package": finding.SeverityMedium}},
		{"stale", "npm", "left-pad", &lockfile.HealthEvidence{Released: "2024-06-14"}, map[string]finding.Severity{"stale-release": finding.SeverityLow}},
		{"just under two years", "npm", "left-pad", &lockfile.HealthEvidence{Released: "2024-06-16"}, nil},
		{"unreadable date is ignored", "npm", "left-pad", &lockfile.HealthEvidence{Released: "sometime"}, nil},
		{"typosquat needs no health", "npm", "lodahs", nil, map[string]finding.Severity{"typosquat-suspect": finding.SeverityMedium}},
		{"all three", "npm", "lodahs", &lockfile.HealthEvidence{Deprecated: "x", Released: "2010-01-01"}, map[string]finding.Severity{
			"typosquat-suspect": finding.SeverityMedium, "deprecated-package": finding.SeverityMedium, "stale-release": finding.SeverityLow,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {
				a.Subject = lockfile.Subject{Ecosystem: tt.eco, Name: tt.pkg}
				a.Evidence.Health = tt.health
			})
			got := map[string]finding.Severity{}
			for _, f := range audit.RunAt(doc, now).Findings {
				switch f.ID {
				case "typosquat-suspect", "deprecated-package", "stale-release":
					got[f.ID] = f.Severity
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for id, sev := range tt.want {
				if got[id] != sev {
					t.Fatalf("%s: got %q, want %q (all: %v)", id, got[id], sev, got)
				}
			}
		})
	}
}

func TestRecentRelease(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	const week = 7 * 24 * time.Hour
	tests := []struct {
		name     string
		min      time.Duration
		health   *lockfile.HealthEvidence
		want     bool
		contains string
	}{
		{"off by default", 0, &lockfile.HealthEvidence{Released: "2026-06-15"}, false, ""},
		{"published today", week, &lockfile.HealthEvidence{Released: "2026-06-15"}, true, "(0 days ago); minimum is 7 days"},
		{"three days ago", week, &lockfile.HealthEvidence{Released: "2026-06-12"}, true, "(3 days ago)"},
		{"exactly old enough", week, &lockfile.HealthEvidence{Released: "2026-06-08"}, false, ""},
		{"old release", week, &lockfile.HealthEvidence{Released: "2024-01-01"}, false, ""},
		{"unknown date is never flagged", week, &lockfile.HealthEvidence{License: "MIT"}, false, ""},
		{"health not collected", week, nil, false, ""},
		{"whole days read as days", 72 * time.Hour, &lockfile.HealthEvidence{Released: "2026-06-14"}, true, "(1 day ago); minimum is 3 days"},
		{"part of a day keeps the duration", 36 * time.Hour, &lockfile.HealthEvidence{Released: "2026-06-15"}, true, "minimum is 36h0m0s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) { a.Evidence.Health = tt.health })
			var got *finding.Finding
			for _, f := range audit.RunWith(doc, audit.Options{Now: now, MinReleaseAge: tt.min}).Findings {
				if f.ID == "recent-release" {
					f := f
					got = &f
				}
			}
			if (got != nil) != tt.want {
				t.Fatalf("finding = %+v, want %v", got, tt.want)
			}
			if got != nil && (got.Severity != finding.SeverityHigh || !strings.Contains(got.Detail, tt.contains)) {
				t.Fatalf("got %+v, want detail containing %q", *got, tt.contains)
			}
		})
	}
}

func TestReleaseDateUnknownIsReportedWhenTheCooldownIsOn(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		eco    string
		health *lockfile.HealthEvidence
		min    time.Duration
		want   bool
	}{
		{"npm without a date", "npm", &lockfile.HealthEvidence{License: "MIT"}, 7 * 24 * time.Hour, true},
		{"npm without health", "npm", nil, 7 * 24 * time.Hour, true},
		{"pypi without health", "pypi", nil, 7 * 24 * time.Hour, true},
		{"a known date is not unknown", "npm", &lockfile.HealthEvidence{Released: "2020-01-01"}, 7 * 24 * time.Hour, false},
		{"cooldown off", "npm", nil, 0, false},
		{"other ecosystems never have release dates", "cargo", nil, 7 * 24 * time.Hour, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {
				a.Subject.Ecosystem = tt.eco
				a.Evidence.Health = tt.health
			})
			var got *finding.Finding
			for _, f := range audit.RunWith(doc, audit.Options{Now: now, MinReleaseAge: tt.min}).Findings {
				if f.ID == "release-date-unknown" {
					f := f
					got = &f
				}
			}
			if (got != nil) != tt.want {
				t.Fatalf("finding = %+v, want %v", got, tt.want)
			}
			if got != nil && got.Severity != finding.SeverityInfo {
				t.Fatalf("severity = %s", got.Severity)
			}
		})
	}
}
