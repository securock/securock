package sast_test

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

type benchCase struct {
	name   string
	files  map[string]string
	want   []string // rules that must be reported
	gap    []string // real vulnerabilities not found yet
	fpGap  []string // safe code reported anyway
	isNone bool
}

var directive = regexp.MustCompile(`(?m)^(?://|#) (want|gap|fp-gap): (.+)$`)

// benchExt is the file name a case is written to; a case may add files with "--- name".
var benchExt = map[string]string{"go": "main.go", "js": "main.js", "ts": "main.ts", "py": "main.py", "java": "Main.java", "php": "main.php", "rb": "main.rb"}

func loadBench(t *testing.T) []benchCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/bench.txt")
	if err != nil {
		t.Fatal(err)
	}
	var cases []benchCase
	for _, part := range strings.Split(string(raw), "\n=== ")[1:] {
		name, src, _ := strings.Cut(part, "\n")
		c := benchCase{name: strings.TrimSpace(name)}
		lang := "go"
		if l, _, ok := strings.Cut(c.name, "/"); ok {
			lang = l
		}
		file, ok := benchExt[lang]
		if !ok {
			t.Fatalf("%s: unknown language", c.name)
		}
		c.files = map[string]string{}
		var cur strings.Builder
		flush := func() { c.files[file] = cur.String(); cur.Reset() }
		for _, line := range strings.SplitAfter(src, "\n") {
			if rest, found := strings.CutPrefix(line, "--- "); found {
				flush()
				file = strings.TrimSpace(rest)
				continue
			}
			cur.WriteString(line)
		}
		flush()
		m := directive.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s: needs a want, gap or fp-gap directive comment", c.name)
		}
		var ids []string
		if m[2] != "none" {
			for _, id := range strings.Split(m[2], ",") {
				ids = append(ids, strings.TrimSpace(id))
			}
		}
		switch m[1] {
		case "want":
			c.want, c.isNone = ids, len(ids) == 0
		case "gap":
			c.gap = ids
		case "fp-gap":
			c.fpGap = ids
		}
		cases = append(cases, c)
	}
	if len(cases) == 0 {
		t.Fatal("no benchmark cases")
	}
	return cases
}

type tally struct{ tp, fp, fn int }

// TestBenchmark runs every corpus case and checks the outcome exactly: a missing
// finding, an extra finding, or a known gap that has quietly been fixed all fail. The
// per-rule precision and recall are logged, and a floor stops them from regressing.
func TestBenchmark(t *testing.T) {
	cases := loadBench(t)
	per := map[string]*tally{}
	bump := func(rule string) *tally {
		if per[rule] == nil {
			per[rule] = &tally{}
		}
		return per[rule]
	}
	for _, c := range cases {
		got := analyze(t, c.files)
		got = slices.Compact(got)
		expect := slices.Clone(c.want)
		expect = append(expect, c.fpGap...)
		slices.Sort(expect)
		if !slices.Equal(got, expect) {
			t.Errorf("%s: reported %v, expected %v", c.name, got, expect)
		}
		for _, id := range c.want {
			bump(id).tp++
		}
		for _, id := range c.gap {
			bump(id).fn++
		}
		for _, id := range c.fpGap {
			bump(id).fp++
		}
		if len(c.want) == 0 && len(c.gap) == 0 && len(c.fpGap) == 0 && !c.isNone {
			t.Errorf("%s: no expectation", c.name)
		}
	}

	var rules []string
	for r := range per {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	var all tally
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-36s %3s %3s %3s  precision  recall\n", "rule", "tp", "fp", "fn")
	for _, r := range rules {
		x := per[r]
		all.tp, all.fp, all.fn = all.tp+x.tp, all.fp+x.fp, all.fn+x.fn
		fmt.Fprintf(&b, "%-36s %3d %3d %3d  %8s  %6s\n", r, x.tp, x.fp, x.fn, pct(x.tp, x.tp+x.fp), pct(x.tp, x.tp+x.fn))
	}
	fmt.Fprintf(&b, "%-36s %3d %3d %3d  %8s  %6s  (%d cases)\n", "all", all.tp, all.fp, all.fn, pct(all.tp, all.tp+all.fp), pct(all.tp, all.tp+all.fn), len(cases))
	t.Log(b.String())

	const minPrecision, minRecall = 0.90, 0.90
	if p := ratio(all.tp, all.tp+all.fp); p < minPrecision {
		t.Errorf("precision %.2f fell below %.2f", p, minPrecision)
	}
	if r := ratio(all.tp, all.tp+all.fn); r < minRecall {
		t.Errorf("recall %.2f fell below %.2f", r, minRecall)
	}
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func pct(a, b int) string { return fmt.Sprintf("%.0f%%", 100*ratio(a, b)) }
