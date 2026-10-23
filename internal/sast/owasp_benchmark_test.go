package sast_test

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/securock/securock/internal/sast"
)

// The OWASP Benchmark suites score the analysis against code it was not written around:
// hundreds of small web handlers, each labeled vulnerable or not, so a true-positive rate
// and a false-positive rate can be measured. They are not vendored. Check one out and
// point the matching variable at it:
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
	scoreBenchmark(t, filepath.Join(dir, "expectedresults-1.2.csv"), filepath.Join(dir, "src", "main", "java"), "sast:java/", map[string]string{
		"sqli": "sql-injection", "cmdi": "command-injection", "pathtraver": "path-traversal", "xss": "xss",
		"ldapi": "ldap-injection", "xpathi": "xpath-injection", "hash": "weak-crypto", "crypto": "weak-crypto",
		"weakrand": "insecure-random", "securecookie": "insecure-cookie", "trustbound": "trust-boundary",
	}, 0.55)
}

func TestOWASPBenchmarkPython(t *testing.T) {
	dir := os.Getenv("SECUROCK_OWASP_BENCHMARK_PYTHON")
	if dir == "" {
		t.Skip("set SECUROCK_OWASP_BENCHMARK_PYTHON to a checkout of BenchmarkPython to run")
	}
	scoreBenchmark(t, filepath.Join(dir, "expectedresults-0.1.csv"), filepath.Join(dir, "testcode"), "sast:py/", map[string]string{
		"sqli": "sql-injection", "cmdi": "command-injection", "pathtraver": "path-traversal", "xss": "xss",
		"ldapi": "ldap-injection", "xpathi": "xpath-injection", "hash": "weak-crypto", "crypto": "weak-crypto",
		"weakrand": "insecure-random", "securecookie": "insecure-cookie", "trustbound": "trust-boundary",
		"codeinj": "code-injection", "deserialization": "insecure-deserialization", "redirect": "open-redirect", "xxe": "xxe",
	}, 0.45)
}

// scoreBenchmark runs the analysis over root and scores it against the labels in csvPath.
// rules maps a Benchmark category to the rule that answers it; the benchmark's own score is
// the true-positive rate minus the false-positive rate, and a tool that guesses scores 0.
func scoreBenchmark(t *testing.T, csvPath, root, prefix string, rules map[string]string, floor float64) {
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
			labels[row[0]] = label{row[1], row[2] == "true"}
		}
	}

	findings, err := sast.Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	testName := regexp.MustCompile(`BenchmarkTest\d+`)
	found := map[string]map[string]bool{}
	for _, f := range findings {
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

	type score struct{ tp, fn, fp, tn int }
	per := map[string]*score{}
	var all score
	for name, l := range labels {
		rule, ok := rules[l.cat]
		if !ok {
			continue
		}
		if per[l.cat] == nil {
			per[l.cat] = &score{}
		}
		hit := found[name][rule]
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
		fmt.Fprintf(&out, "%-16s %5.0f%% %5.0f%%  %5d %5d %5d %5d\n", c, 100*rate(s.tp, s.fn), 100*rate(s.fp, s.tn), s.tp, s.fn, s.fp, s.tn)
	}
	tpr, fpr := rate(all.tp, all.fn), rate(all.fp, all.tn)
	fmt.Fprintf(&out, "%-16s %5.0f%% %5.0f%%  %5d %5d %5d %5d   score %+.2f\n", "ALL", 100*tpr, 100*fpr, all.tp, all.fn, all.fp, all.tn, tpr-fpr)
	t.Log(out.String())

	if tpr-fpr < floor {
		t.Errorf("benchmark score %.2f fell below %.2f", tpr-fpr, floor)
	}
}
