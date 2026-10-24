package sast_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/securock/securock/internal/sast"
)

// PyGoat has no upstream safe/vulnerable label CSV. These manually reviewed
// cases cover selected Python labs, not every challenge or finding in the app.
// See docs/sast-benchmarks.md for the pinned revision and label rationale.
func TestPyGoat(t *testing.T) {
	root := os.Getenv("SECUROCK_PYGOAT")
	if root == "" {
		t.Skip("set SECUROCK_PYGOAT to the pinned PyGoat checkout to run")
	}
	// Pin the reviewed source and templates, including evidence for known misses.
	// A different checkout must not silently change the meaning of these labels.
	inputs := []struct{ path, sha256 string }{
		{"command_injection_lab/app.py", "43af219c885b2948c308d3756b1a70e12b12f93ca13b7e049bb103d577e46dcc"},
		{"crypto_failure_lab/app.py", "50aa54e576db335a59677160ea2ae18dd69212cffde2969cf397208a97dd6c17"},
		{"insec_des_lab/main.py", "7e7e6707e16935692ee0c1d7535b7741502a624de0d4d3dea945a82a968a8ec7"},
		{"software_integrity_lab/app.py", "d324aa809c7d2936d0f04649b314fb9a5bf4c432e3b3ccc672ac2f0ed98df33f"},
		{"sql_injection_lab/app.py", "9a58b6da6a7c8e52ccccf70bde96e84b2ff71eb63a69dfea3be11c40c8e5fd5a"},
		{"ssrf_lab/app.py", "862d84dea045ba4ecfe17bf09a99fcfbd148d4457e9da313fb09e7332cafd08b"},
		{"template_injection_lab/app.py", "e5c7716ecc11e6a1de9024fb518d572e83ebf294096846ef118fbb4777a07da8"},
		{"xss_lab/app.py", "dbcff08fec013d1fde896ac880ec2ab8441e7248cca58cbeed40f6e93f4723b4"},
		{"xxe_lab/app.py", "50a43aa0bad0d4604b33722c8465e24822d95dfb2ebfbce067589815b113e002"},
		{"xss_lab/templates/lab1.html", "801a7a7fa453de38ce9a2d13c2a8147d4dd0d5c416a3ea441e89e65458e93c3c"},
		{"xss_lab/templates/lab2.html", "e82479e0439953ba8c758739176589eb84afbff9c937052e5b0f7f98ea1975c4"},
		{"xss_lab/templates/lab3.html", "c8f2f51d4ec77a3fd4dbe4cfdf1feb71b9cc3bd85b38520ce22a194d242ae3af"},
	}
	for _, input := range inputs {
		data, err := os.ReadFile(filepath.Join(root, "dockerized_labs", filepath.FromSlash(input.path)))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != input.sha256 {
			t.Fatalf("PyGoat input %s changed; use revision 46fef968f3f44d1191363baf936aaa3335dc5c6d", input.path)
		}
	}
	type label struct {
		lab, file, function, rule string
		vulnerable, required      bool
	}
	cases := []label{
		{"sql_injection_lab", "app.py", "lab", "sql-injection", true, true},
		{"sql_injection_lab", "app.py", "init_db", "sql-injection", false, false},
		{"command_injection_lab", "app.py", "lab1", "command-injection", true, true},
		{"command_injection_lab", "app.py", "lab2", "code-injection", true, true},
		{"ssrf_lab", "app.py", "lab1", "path-traversal", true, true},
		{"ssrf_lab", "app.py", "lab2", "ssrf", true, true},
		{"insec_des_lab", "main.py", "deserialize_data", "insecure-deserialization", true, true},
		{"insec_des_lab", "main.py", "serialize_data", "insecure-deserialization", false, false},
		{"software_integrity_lab", "app.py", "lab1", "insecure-deserialization", true, true},
		{"crypto_failure_lab", "app.py", "lab1", "weak-crypto", true, true},
		{"crypto_failure_lab", "app.py", "custom_hash", "weak-crypto", true, true},
		{"xxe_lab", "app.py", "xxe_parse", "xxe", true, true},
		{"xss_lab", "app.py", "lab1", "xss", true, false},
		{"xss_lab", "app.py", "lab2", "xss", true, false},
		{"xss_lab", "app.py", "lab3", "xss", true, false},
		{"template_injection_lab", "app.py", "view_blog", "code-injection", true, false},
	}
	// Each Flask lab is a separate application. Analyzing the repository as one
	// project conflates unrelated app.py modules and their same-named functions.
	labs := map[string]bool{}
	for _, c := range cases {
		labs[c.lab] = true
	}
	var names []string
	for name := range labs {
		names = append(names, name)
	}
	sort.Strings(names)
	type score struct{ tp, fn, fp, tn int }
	per := map[string]*score{}
	var all score
	incomplete := 0
	for _, lab := range names {
		dir := filepath.Join(root, "dockerized_labs", lab)
		findings, err := sast.Analyze(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "sast:analysis-incomplete" {
				incomplete++
				t.Errorf("%s: analysis incomplete: %v", lab, f.Location)
			}
		}
		for _, c := range cases {
			if c.lab != lab {
				continue
			}
			source, err := os.ReadFile(filepath.Join(dir, c.file))
			if err != nil {
				t.Fatal(err)
			}
			start, end, err := pyGoatFunctionLines(string(source), c.function)
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			for _, f := range findings {
				if f.ID == "sast:py/"+c.rule && f.Location != nil && f.Location.File == c.file && f.Location.Line >= start && f.Location.Line <= end {
					hit = true
				}
			}
			if per[c.rule] == nil {
				per[c.rule] = &score{}
			}
			outcome := "TN"
			for _, s := range []*score{per[c.rule], &all} {
				switch {
				case c.vulnerable && hit:
					s.tp++
					outcome = "TP"
				case c.vulnerable:
					s.fn++
					outcome = "FN"
				case hit:
					s.fp++
					outcome = "FP"
				default:
					s.tn++
				}
			}
			t.Logf("%s %s %s/%s:%s", c.rule, outcome, lab, c.file, c.function)
			if c.required && !hit {
				t.Errorf("lost detection: %s/%s:%s (%s)", lab, c.file, c.function, c.rule)
			}
			if !c.vulnerable && hit {
				t.Errorf("false positive: %s/%s:%s (%s)", lab, c.file, c.function, c.rule)
			}
		}
	}
	var rules []string
	for rule := range per {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	var out strings.Builder
	fmt.Fprintf(&out, "\n%-26s %4s %4s %4s %4s\n", "category", "TP", "FN", "FP", "TN")
	for _, rule := range rules {
		s := per[rule]
		fmt.Fprintf(&out, "%-26s %4d %4d %4d %4d\n", rule, s.tp, s.fn, s.fp, s.tn)
	}
	fmt.Fprintf(&out, "%-26s %4d %4d %4d %4d\nanalysis-incomplete findings: %d", "ALL", all.tp, all.fn, all.fp, all.tn, incomplete)
	t.Log(out.String())
}

// The selected functions are top-level Python definitions. Match their exact
// names so another handler's finding cannot satisfy a missing detection.
func pyGoatFunctionLines(source, name string) (int, int, error) {
	lines := strings.Split(source, "\n")
	start, end := 0, len(lines)
	for i, line := range lines {
		if strings.HasPrefix(line, "def "+name+"(") {
			if start != 0 {
				return 0, 0, fmt.Errorf("duplicate PyGoat function %s; check the suite revision", name)
			}
			start = i + 1
			continue
		}
		if start != 0 && end == len(lines) && (strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "class ") || strings.HasPrefix(line, "@") || strings.HasPrefix(line, "if __name__")) {
			end = i
		}
	}
	if start == 0 {
		return 0, 0, fmt.Errorf("missing PyGoat function %s; check the suite revision", name)
	}
	return start, end, nil
}

func TestPyGoatFunctionLines(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		start, end   int
		wantError    bool
	}{
		{"neighboring handler", "def lab():\n    pass\ndef lab2():\n    eval(data)\n", 1, 2, false},
		{"decorated neighbor", "def lab():\n    pass\n@app.route('/')\ndef lab2():\n    eval(data)\n", 1, 2, false},
		{"nested definition", "def lab():\n    def nested():\n        pass\n    eval(data)\nif __name__ == '__main__':\n    app.run()\n", 1, 4, false},
		{"last function", "def lab():\n    eval(data)", 1, 2, false},
		{"different function", "def lab2():\n    eval(data)\n", 0, 0, true},
		{"duplicate function", "def lab():\n    pass\ndef lab():\n    eval(data)\n", 0, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := pyGoatFunctionLines(tt.source, "lab")
			if (err != nil) != tt.wantError || start != tt.start || end != tt.end {
				t.Fatalf("got (%d, %d, %v), want (%d, %d), error=%t", start, end, err, tt.start, tt.end, tt.wantError)
			}
		})
	}
}
