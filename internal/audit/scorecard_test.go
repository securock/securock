package audit_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/scorecard"
	"github.com/securock/securock/pkg/lockfile"
)

func TestLowScorecard(t *testing.T) {
	tests := []struct {
		name string
		min  float64
		res  *scorecard.Result
		want bool
		note string
	}{
		{"below the minimum", 5, &scorecard.Result{Repository: "github.com/o/r", Score: 3.2}, true, "claims, not verified"},
		{"verified repository", 5, &scorecard.Result{Repository: "github.com/o/r", Score: 3.2, Verified: true}, true, "3.2 of 10"},
		{"at the minimum", 5, &scorecard.Result{Repository: "github.com/o/r", Score: 5}, false, ""},
		{"above the minimum", 5, &scorecard.Result{Repository: "github.com/o/r", Score: 9.1}, false, ""},
		{"check is off", 0, &scorecard.Result{Repository: "github.com/o/r", Score: 0.5}, false, ""},
		{"no scorecard", 5, nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {})
			opts := audit.Options{MinScorecard: tt.min}
			if tt.res != nil {
				opts.Scorecards = map[string]scorecard.Result{doc.Artifacts[0].ArtifactID(): *tt.res}
			}
			var got *finding.Finding
			for _, f := range audit.RunWith(doc, opts).Findings {
				if f.ID == "low-scorecard" {
					got = &f
				}
			}
			if (got != nil) != tt.want {
				t.Fatalf("finding = %+v, want present: %v", got, tt.want)
			}
			if got != nil && (got.Severity != finding.SeverityMedium || !strings.Contains(got.Detail, tt.note)) {
				t.Fatalf("unexpected finding: %+v", got)
			}
		})
	}
}

func TestScorecardUncheckedIsReported(t *testing.T) {
	doc := artifact(func(a *lockfile.Artifact) {})
	var found *finding.Finding
	for _, f := range audit.RunWith(doc, audit.Options{MinScorecard: 5, ScorecardUnchecked: "1 of 1 packages have no Scorecard"}).Findings {
		if f.ID == "scorecard-unchecked" {
			found = &f
		}
	}
	if found == nil || found.Severity != finding.SeverityInfo {
		t.Fatalf("a missing score must be reported as info: %+v", found)
	}
	for _, f := range audit.RunWith(doc, audit.Options{}).Findings {
		if f.ID == "scorecard-unchecked" {
			t.Fatal("nothing to report when the check was not asked for")
		}
	}
}

func TestLowScorecardChecks(t *testing.T) {
	res := scorecard.Result{
		Repository: "github.com/o/r",
		Score:      9,
		Checks:     map[string]float64{"Dangerous-Workflow": 0, "Maintained": 10, "Code-Review": 4},
	}
	tests := []struct {
		name   string
		checks map[string]float64
		want   []string
	}{
		{"a failing check", map[string]float64{"Dangerous-Workflow": 5}, []string{"low-scorecard-check:Dangerous-Workflow"}},
		{"a passing check", map[string]float64{"Maintained": 5}, nil},
		{"at the minimum", map[string]float64{"Code-Review": 4}, nil},
		{"two failing checks, in name order", map[string]float64{"Dangerous-Workflow": 1, "Code-Review": 5},
			[]string{"low-scorecard-check:Code-Review", "low-scorecard-check:Dangerous-Workflow"}},
		{"a check the repository has no score for is not judged", map[string]float64{"Packaging": 10}, nil},
		{"no rule", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := artifact(func(a *lockfile.Artifact) {})
			opts := audit.Options{
				ScorecardChecks: tt.checks,
				Scorecards:      map[string]scorecard.Result{doc.Artifacts[0].ArtifactID(): res},
			}
			var got []string
			for _, f := range audit.RunWith(doc, opts).Findings {
				if strings.HasPrefix(f.ID, "low-scorecard") {
					got = append(got, f.ID)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOverallAndCheckFindingsAreIndependent(t *testing.T) {
	doc := artifact(func(a *lockfile.Artifact) {})
	opts := audit.Options{
		MinScorecard:    8,
		ScorecardChecks: map[string]float64{"Code-Review": 5},
		Scorecards: map[string]scorecard.Result{doc.Artifacts[0].ArtifactID(): {
			Repository: "github.com/o/r", Score: 6, Checks: map[string]float64{"Code-Review": 2},
		}},
	}
	ids := map[string]bool{}
	for _, f := range audit.RunWith(doc, opts).Findings {
		ids[f.ID] = true
	}
	if !ids["low-scorecard"] || !ids["low-scorecard-check:Code-Review"] {
		t.Fatalf("both the overall score and the check should be reported: %v", ids)
	}
}
