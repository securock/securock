package quality_test

import (
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/quality"
	"github.com/securock/securock/internal/validation"
	"os"
	"path/filepath"
	"testing"
)

func TestTruthLabelsAndUnknownCoverage(t *testing.T) {
	step := validation.Step{Name: "fixture", Expected: []string{"sast:real"}, Forbidden: []string{"sast:false"}}
	result, e := quality.Evaluate(step, finding.New("security", []finding.Finding{{ID: "sast:real"}, {ID: "sast:false"}, {ID: "sast:unlabeled"}}), nil)
	if e != nil || result.TP != 1 || result.FP != 1 || len(result.Unlabeled) != 1 {
		t.Fatal(result, e)
	}
	r := quality.Aggregate([]quality.Result{result}, "fixture", "engine", .4, 1)
	if r.Passed || r.Precision == nil || *r.Precision != .5 {
		t.Fatal(r)
	}
	missing, e := quality.Evaluate(step, finding.New("security", nil), fmt.Errorf("incomplete"))
	if e != nil || missing.FN != 1 || !missing.Incomplete {
		t.Fatal(missing, e)
	}
	if quality.Aggregate([]quality.Result{missing}, "fixture", "engine", 0, 0).Passed {
		t.Fatal("unknown treated as success")
	}
	step.Forbidden = append(step.Forbidden, "sast:real")
	if _, e = quality.Evaluate(step, finding.New("security", nil), nil); e == nil {
		t.Fatal("contradictory truth accepted")
	}
}
func TestFixtureChangesInvalidateComparison(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "source.go")
	_ = os.WriteFile(file, []byte("vulnerable"), 0600)
	suite := validation.Suite{Version: 1, Steps: []validation.Step{{Name: "fixture", Command: "security", Expected: []string{"rule"}}}}
	before, e := quality.FixtureDigest(dir, suite)
	if e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(file, []byte("fixed"), 0600)
	after, e := quality.FixtureDigest(dir, suite)
	if e != nil || before == after {
		t.Fatal("fixture change missed", e)
	}
}
