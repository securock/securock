package sast_test

import (
	"encoding/csv"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/securock/securock/internal/sast"
)

// The OWASP Benchmark suites are development/regression benchmarks, not a held-out
// evaluation: their failures inform fixes. Each handler is labeled vulnerable or safe.
// They are not vendored; pinned revisions and measurement details are in
// docs/sast-benchmarks.md. Check one out and point the matching variable at it:
//
//	git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava
//	SECUROCK_OWASP_BENCHMARK=$PWD/BenchmarkJava go test ./internal/sast -run OWASPBenchmark -v
//
//	git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython
//	SECUROCK_OWASP_BENCHMARK_PYTHON=$PWD/BenchmarkPython go test ./internal/sast -run OWASPBenchmark -v
func TestOWASPBenchmarkJava(t *testing.T) {
	dir := os.Getenv("SECUROCK_OWASP_BENCHMARK")
	if dir == "" {
		t.Skip("set SECUROCK_OWASP_BENCHMARK to a checkout of BenchmarkJava to run")
	}
	scoreBenchmark(t, filepath.Join(dir, "expectedresults-1.2.csv"), filepath.Join(dir, "src", "main"), "sast:java/", map[string]string{
		"sqli": "sql-injection", "cmdi": "command-injection", "pathtraver": "path-traversal", "xss": "xss",
		"ldapi": "ldap-injection", "xpathi": "xpath-injection", "hash": "weak-crypto", "crypto": "weak-crypto",
		"weakrand": "insecure-random", "securecookie": "insecure-cookie", "trustbound": "trust-boundary",
	}, 2740, map[string]benchmarkLimit{
		"cmdi": {126, 0}, "crypto": {130, 0}, "hash": {129, 0}, "ldapi": {27, 0},
		"pathtraver": {133, 0}, "securecookie": {36, 0}, "sqli": {272, 0},
		"trustbound": {79, 0}, "weakrand": {218, 0}, "xpathi": {15, 0}, "xss": {246, 13},
	})
}

func TestOWASPBenchmarkPython(t *testing.T) {
	dir := os.Getenv("SECUROCK_OWASP_BENCHMARK_PYTHON")
	if dir == "" {
		t.Skip("set SECUROCK_OWASP_BENCHMARK_PYTHON to a checkout of BenchmarkPython to run")
	}
	// Include helpers imported by the handlers; scanning testcode alone turns local
	// wrappers and sanitizers into unknown third-party calls.
	scoreBenchmark(t, filepath.Join(dir, "expectedresults-0.1.csv"), dir, "sast:py/", map[string]string{
		"sqli": "sql-injection", "cmdi": "command-injection", "pathtraver": "path-traversal", "xss": "xss",
		"ldapi": "ldap-injection", "xpathi": "xpath-injection", "hash": "weak-crypto", "crypto": "weak-crypto",
		"weakrand": "insecure-random", "securecookie": "insecure-cookie", "trustbound": "trust-boundary",
		"codeinj": "code-injection", "deserialization": "insecure-deserialization", "redirect": "open-redirect", "xxe": "xxe",
	}, 1230, map[string]benchmarkLimit{
		"cmdi": {13, 1}, "codeinj": {20, 12}, "deserialization": {18, 1}, "hash": {71, 0},
		"ldapi": {16, 0}, "pathtraver": {60, 18}, "redirect": {13, 8}, "securecookie": {24, 0},
		"sqli": {5, 0}, "trustbound": {18, 3}, "weakrand": {99, 0}, "xpathi": {51, 5},
		"xss": {31, 11}, "xxe": {8, 7},
	})
}

// Guard recall and false alarms separately in every category: an aggregate score
// must not hide losing SQL detections by improving an unrelated rule.
type benchmarkLimit struct{ minTP, maxFP int }

// scoreBenchmark runs the analysis over root and scores it against the labels in csvPath.
// rules maps a Benchmark category to the rule that answers it; the benchmark's own score is
// the true-positive rate minus the false-positive rate, and a tool that guesses scores 0.
func scoreBenchmark(t *testing.T, csvPath, root, prefix string, rules map[string]string, total int, limits map[string]benchmarkLimit) {
	t.Helper()
	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.Comment = '#'
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	type label struct {
		cat  string
		real bool
	}
	labels := map[string]label{}
	for _, row := range rows {
		if len(row) >= 3 && strings.HasPrefix(row[0], "BenchmarkTest") {
			if _, duplicate := labels[row[0]]; duplicate || (row[2] != "true" && row[2] != "false") {
				t.Fatalf("invalid or duplicate label: %v", row)
			}
			labels[row[0]] = label{row[1], row[2] == "true"}
		}
	}
	if len(labels) != total {
		t.Fatalf("expected %d labels, got %d; check the suite revision", total, len(labels))
	}
	available := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(path) == ".java" || filepath.Ext(path) == ".py") {
			available[strings.TrimSuffix(d.Name(), filepath.Ext(path))] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, label := range labels {
		if !available[name] {
			t.Errorf("labeled source file missing: %s", name)
		}
		if _, ok := rules[label.cat]; !ok {
			t.Errorf("unmapped benchmark category: %s", label.cat)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	findings, err := sast.Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	testName := regexp.MustCompile(`BenchmarkTest\d+`)
	found := map[string]map[string]bool{}
	var incomplete []string
	for _, f := range findings {
		if f.ID == "sast:analysis-incomplete" && f.Location != nil {
			incomplete = append(incomplete, f.Location.File)
		}
		if f.Location == nil {
			continue
		}
		if n := testName.FindString(f.Location.File); n != "" {
			if found[n] == nil {
				found[n] = map[string]bool{}
			}
			found[n][strings.TrimPrefix(f.ID, prefix)] = true
		}
	}
	if len(incomplete) != 0 {
		t.Errorf("benchmark analysis incomplete: %d findings", len(incomplete))
	}

	type score struct{ tp, fn, fp, tn int }
	per := map[string]*score{}
	var all score
	var mismatches []string
	for name, l := range labels {
		rule := rules[l.cat]
		if per[l.cat] == nil {
			per[l.cat] = &score{}
		}
		hit := found[name][rule]
		if hit != l.real {
			outcome := "FP"
			if l.real {
				outcome = "FN"
			}
			mismatches = append(mismatches, fmt.Sprintf("%s %s %s", l.cat, outcome, name))
		}
		for _, s := range []*score{per[l.cat], &all} {
			switch {
			case l.real && hit:
				s.tp++
			case l.real:
				s.fn++
			case hit:
				s.fp++
			default:
				s.tn++
			}
		}
	}
	rate := func(a, b int) float64 {
		if a+b == 0 {
			return 0
		}
		return float64(a) / float64(a+b)
	}
	var cats []string
	for c := range per {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	var out strings.Builder
	fmt.Fprintf(&out, "\n%-16s %6s %6s  %5s %5s %5s %5s\n", "category", "TPR", "FPR", "tp", "fn", "fp", "tn")
	for _, c := range cats {
		s := per[c]
		fmt.Fprintf(&out, "%-16s %5.1f%% %5.1f%%  %5d %5d %5d %5d\n", c, 100*rate(s.tp, s.fn), 100*rate(s.fp, s.tn), s.tp, s.fn, s.fp, s.tn)
		limit, ok := limits[c]
		if !ok || s.tp < limit.minTP || s.fp > limit.maxFP {
			t.Errorf("%s: tp=%d (minimum %d), fp=%d (maximum %d)", c, s.tp, limit.minTP, s.fp, limit.maxFP)
		}
	}
	tpr, fpr := rate(all.tp, all.fn), rate(all.fp, all.tn)
	fmt.Fprintf(&out, "%-16s %5.1f%% %5.1f%%  %5d %5d %5d %5d   score %+.4f\n", "ALL", 100*tpr, 100*fpr, all.tp, all.fn, all.fp, all.tn, tpr-fpr)
	fmt.Fprintf(&out, "analysis-incomplete findings: %d (cases remain in the score denominator)\n", len(incomplete))
	t.Log(out.String())
	if os.Getenv("SECUROCK_BENCHMARK_DETAILS") != "" {
		sort.Strings(mismatches)
		t.Log("misclassified cases:\n" + strings.Join(mismatches, "\n"))
		sort.Strings(incomplete)
		t.Log("incomplete analysis:\n" + strings.Join(incomplete, "\n"))
	}
}
