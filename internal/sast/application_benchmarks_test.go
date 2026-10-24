package sast_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
)

type applicationInput struct{ file, sha256 string }

// Labels are reviewed source/rule ranges, not the application's challenge names.
// Known misses and false positives remain scored; improvements are allowed.
type applicationCase struct {
	file, rule                    string
	start, end                    int
	vulnerable, required, knownFP bool
}

type applicationProject struct {
	inputs []applicationInput
	cases  []applicationCase
}

func (c applicationCase) hit(findings []finding.Finding) bool {
	for _, f := range findings {
		if f.ID == c.rule && f.Location != nil && f.Location.File == c.file && f.Location.Line >= c.start && f.Location.Line <= c.end {
			return true
		}
	}
	return false
}

func (c applicationCase) regression(hit bool) error {
	if c.required && !hit {
		return fmt.Errorf("lost detection: %s:%d-%d (%s)", c.file, c.start, c.end, c.rule)
	}
	if !c.vulnerable && hit && !c.knownFP {
		return fmt.Errorf("new false positive: %s:%d-%d (%s)", c.file, c.start, c.end, c.rule)
	}
	return nil
}

func readApplicationProject(root string, p applicationProject) (map[string][]byte, error) {
	if len(p.inputs) == 0 || len(p.cases) == 0 {
		return nil, fmt.Errorf("application project needs inputs and labels")
	}
	files := map[string][]byte{}
	for _, input := range p.inputs {
		if !filepath.IsLocal(input.file) || strings.Contains(input.file, "\\") || filepath.ToSlash(filepath.Clean(input.file)) != input.file {
			return nil, fmt.Errorf("invalid input path %q", input.file)
		}
		if _, exists := files[input.file]; exists {
			return nil, fmt.Errorf("duplicate input %s", input.file)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(input.file)))
		if err != nil {
			return nil, err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != input.sha256 {
			return nil, fmt.Errorf("input %s changed; use the documented pinned revision", input.file)
		}
		files[input.file] = data
	}
	for i, c := range p.cases {
		data, exists := files[c.file]
		if !exists || c.start < 1 || c.end < c.start || c.end > len(strings.Split(string(data), "\n")) || !strings.HasPrefix(c.rule, "sast:") || (c.required && !c.vulnerable) || (c.knownFP && c.vulnerable) {
			return nil, fmt.Errorf("invalid label %s:%d-%d (%s)", c.file, c.start, c.end, c.rule)
		}
		for _, previous := range p.cases[:i] {
			if previous.file == c.file && previous.rule == c.rule && previous.start <= c.end && c.start <= previous.end {
				return nil, fmt.Errorf("overlapping labels %s:%d-%d (%s)", c.file, c.start, c.end, c.rule)
			}
		}
	}
	return files, nil
}

func runApplicationBenchmark(t *testing.T, env, revision string, projects []applicationProject) {
	t.Helper()
	root := os.Getenv(env)
	if root == "" {
		t.Skipf("set %s to revision %s to run", env, revision)
	}
	if len(projects) == 0 {
		t.Fatal("no application projects")
	}
	type score struct{ tp, fn, fp, tn int }
	per := map[string]*score{}
	var all score
	incomplete := 0
	for _, p := range projects {
		files, err := readApplicationProject(root, p)
		if err != nil {
			t.Fatalf("%s revision %s: %v", env, revision, err)
		}
		// Only checksum-pinned inputs are analyzed. Separate projects keep mutually
		// exclusive code-fix/security variants from sharing globals and summaries.
		dir := t.TempDir()
		for _, input := range p.inputs {
			path := filepath.Join(dir, filepath.FromSlash(input.file))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, files[input.file], 0o600); err != nil {
				t.Fatal(err)
			}
		}
		findings, err := sast.Analyze(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "sast:analysis-incomplete" {
				incomplete++
				t.Errorf("analysis incomplete: %v", f.Location)
			}
		}
		for _, c := range p.cases {
			hit := c.hit(findings)
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
			t.Logf("%s %s %s:%d-%d", c.rule, outcome, c.file, c.start, c.end)
			if err := c.regression(hit); err != nil {
				t.Error(err)
			}
		}
	}
	var rules []string
	for rule := range per {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	var out strings.Builder
	fmt.Fprintf(&out, "\n%-30s %4s %4s %4s %4s\n", "category", "TP", "FN", "FP", "TN")
	for _, rule := range rules {
		s := per[rule]
		fmt.Fprintf(&out, "%-30s %4d %4d %4d %4d\n", rule, s.tp, s.fn, s.fp, s.tn)
	}
	fmt.Fprintf(&out, "%-30s %4d %4d %4d %4d\nanalysis-incomplete findings: %d", "ALL", all.tp, all.fn, all.fp, all.tn, incomplete)
	t.Log(out.String())
}

func TestNodeGoat(t *testing.T) {
	runApplicationBenchmark(t, "SECUROCK_NODEGOAT", "c5cb68a7084e4ae7dcc60e6a98768720a81841e8", []applicationProject{{
		inputs: []applicationInput{
			{"app/routes/allocations.js", "b5b7da1a6b595799cf6cca402756dd9a3f6e2a8b5d712c1989d23b7f01f349a6"},
			{"app/routes/benefits.js", "bc5516b35ba21884915b88b3f810441e616f068d8a0cf756b143185d5aeda2d2"},
			{"app/routes/contributions.js", "196bdeaa22da4cfe8a851b1b932710b2fcedd21f14ed75d70b739ba759a01003"},
			{"app/routes/error.js", "452dc61f9f06a31ea4305edb2e573fc940428615841533b59320792fcfb6fb3f"},
			{"app/routes/index.js", "3ab970b2888bc1501515db24a83cc7851ac9c09d00948c652300401515185eb5"},
			{"app/routes/memos.js", "c3543f308f24083436e25e3a72210ad31e611db5c93268d8dd0e340095e132c9"},
			{"app/routes/profile.js", "18575bf3d3710906e57e09e6036e40fd3986bdcca436ed0e2a2875b41f0f2aca"},
			{"app/routes/research.js", "e399f3c70436fa160f00835626bf50f88980268fcd143436af97c9d2297c1d92"},
			{"app/routes/session.js", "e53e38b6eea76b026efaacde07f694e7a2eca005de4083fb74f9393d432a5b25"},
			{"app/routes/tutorial.js", "502e0b959b37cbc844d15eadd7a78a40b5281155fcf8d532f0e4abdd2fee8eb9"},
			{"app/data/allocations-dao.js", "c6aebc971ce7f9c8b2a8f0864a500497de25a3ea0318ef94ecd57cadf6e789ea"},
			{"app/data/benefits-dao.js", "0ac30b097e016eeffb10e1c72d9c657153d3ce67e7b3f4756b2cb127d94181d7"},
			{"app/data/contributions-dao.js", "363065e8b3c32f0997ce2dcb17341eb3e40b7f43b00b72c576dfebf73f551c85"},
			{"app/data/memos-dao.js", "6582195bd913c2d60d63e9b519f9508a3319e07e158fd0c6f31dcbc50a80e8cf"},
			{"app/data/profile-dao.js", "80429a5df579867401a59b1cbd9c1d74f88d5548780fbd909e9504876c1968cc"},
			{"app/data/research-dao.js", "f1cf267e56080fc94943ad7d83802b4e9db9420687fac49f84dbc0e45dfa88ac"},
			{"app/data/user-dao.js", "577fb140933a50e010a4bbcb74e975f678d7f3a989467e4d113926f35c042e64"},
			{"config/config.js", "b84b1bf634159caffdef50fe826077e60dbde1e381ceb148ff3b869e789b6962"},
		},
		cases: []applicationCase{
			{"app/routes/contributions.js", "sast:js/code-injection", 32, 34, true, true, false},
			{"app/data/allocations-dao.js", "sast:js/nosql-injection", 86, 86, true, true, false},
			{"app/routes/research.js", "sast:js/ssrf", 16, 16, true, true, false},
			{"app/routes/index.js", "sast:js/open-redirect", 72, 72, true, true, false},
			{"app/routes/session.js", "sast:js/open-redirect", 36, 42, false, false, false},
		},
	}})
}

// These standalone upstream code-fix fragments deliberately have unresolved
// application globals. They must not be merged into a single synthetic app.
func TestJuiceShop(t *testing.T) {
	inputs := []applicationInput{
		{"routes/search.ts", "6e3272ef4065d080295d995a04964e8c5e6b1e06c4b4c8ebed3234286686ee5f"},
		{"data/static/codefixes/unionSqlInjectionChallenge_1.ts", "20c2d1c6b6bd85b489abb4c2ecbf054dcbc177f167eeffe268329f2979209504"},
		{"data/static/codefixes/unionSqlInjectionChallenge_2_correct.ts", "1d9469f18d5c1f5bfc37312fa8f1e5f5db953c52860f65f7d0f21ca26eeb3de0"},
		{"data/static/codefixes/unionSqlInjectionChallenge_3.ts", "107ff063f641b01c6ece82177af8ce2b1eaa305d3d8ce4202ae74fd211fb7c53"},
		{"data/static/codefixes/noSqlReviewsChallenge_1.ts", "516ba4eecc6c65c83d8cf3597dbcaad6cd5ded1915d125518554ea625e664cbc"},
		{"data/static/codefixes/noSqlReviewsChallenge_2.ts", "c3ba5bece5b047feac13f447df833e95388e5bb0d36e25b5aa70fe800b78e40b"},
		{"data/static/codefixes/noSqlReviewsChallenge_3_correct.ts", "91a37d919710a5661f42478955841489d417504a5802be3cb26c2d78412297a8"},
	}
	cases := []applicationCase{
		{inputs[0].file, "sast:js/sql-injection", 23, 23, true, true, false},
		{inputs[0].file, "sast:js/sql-injection", 47, 47, false, false, false},
		{inputs[1].file, "sast:js/sql-injection", 6, 6, true, true, false},
		{inputs[2].file, "sast:js/sql-injection", 5, 8, false, false, false},
		// No string starts with both apple and orange: the rejecting OR always
		// returns before the query. This is safe for SQL, not a working fix.
		{inputs[3].file, "sast:js/sql-injection", 10, 10, false, false, false},
		{inputs[4].file, "sast:js/nosql-injection", 10, 13, true, true, false},
		{inputs[5].file, "sast:js/nosql-injection", 4, 7, true, true, false},
		{inputs[6].file, "sast:js/nosql-injection", 10, 13, false, false, false},
	}
	projects, err := singleFileApplications(inputs, cases)
	if err != nil {
		t.Fatal(err)
	}
	runApplicationBenchmark(t, "SECUROCK_JUICE_SHOP", "717f5efa886b0417eeecb52378b03cf10567b7e2", projects)
}

func TestDVWA(t *testing.T) {
	inputs := []applicationInput{
		{"vulnerabilities/sqli/source/low.php", "652bb44d14a9d81c9245f05ed8440beecf7977e982e00d3ddb916126a72e85bf"},
		{"vulnerabilities/sqli/source/impossible.php", "f4dcc92946933a31b0e93362a184ff776da9736036e99bec79f119cc2128aa8c"},
		{"vulnerabilities/exec/source/low.php", "399a0d5dd28436a952a5bb0d14390eb421e57ab2e7add68813b6ce283cc70f28"},
		{"vulnerabilities/exec/source/medium.php", "c25e0a1a61a4c36eedad8c0d54178e88d030f3c2886fe34edea5ae5054c398c0"},
		{"vulnerabilities/exec/source/high.php", "e3b703d6180c5c1e62fd09f78036e193a16025ffe208be9d90bb19d71a08db7f"},
		{"vulnerabilities/exec/source/impossible.php", "26b294a69538ae5de36b8669fdaef85022814bfaa253f7678b2ac5fa295ab543"},
		{"vulnerabilities/open_redirect/source/low.php", "d9839b61e112df946429ec3b8f2de8a3e4f0ac741842fcd34cce0a1ab3363861"},
		{"vulnerabilities/open_redirect/source/medium.php", "634fdfb18bea35460f920bc4e22a5501975f61eb361886f093edf715895cbd17"},
		{"vulnerabilities/open_redirect/source/high.php", "2d6d53feca779f9c93303a2e0a975882a033ab42ba545acd457555580fe05072"},
		{"vulnerabilities/open_redirect/source/impossible.php", "82c04f35908168ad2d4f948006c89a5fd6586cf335b771963ed839a7d06dd22a"},
		{"vulnerabilities/sqli/source/medium.php", "dd81afdddf5817294f2eea11ffaf21b2aad90cb768cc3d57ef9b6d0f96020db4"},
	}
	cases := []applicationCase{
		{inputs[0].file, "sast:php/sql-injection", 8, 52, true, true, false},
		{inputs[1].file, "sast:php/sql-injection", 14, 57, false, false, false},
		{inputs[2].file, "sast:php/command-injection", 8, 15, true, true, false},
		{inputs[3].file, "sast:php/command-injection", 17, 24, true, true, false},
		{inputs[4].file, "sast:php/command-injection", 24, 31, true, true, false},
		{inputs[5].file, "sast:php/command-injection", 20, 27, false, false, false},
		{inputs[6].file, "sast:php/open-redirect", 4, 4, true, true, false},
		{inputs[7].file, "sast:php/open-redirect", 11, 11, true, true, false},
		{inputs[8].file, "sast:php/open-redirect", 5, 5, true, true, false},
		{inputs[9].file, "sast:php/open-redirect", 18, 18, false, false, false},
		// Escaping quotes does not protect an unquoted SQL expression.
		{inputs[10].file, "sast:php/sql-injection", 10, 49, true, true, false},
	}
	projects, err := singleFileApplications(inputs, cases)
	if err != nil {
		t.Fatal(err)
	}
	runApplicationBenchmark(t, "SECUROCK_DVWA", "a1978a2fed195acd093010af6395f86a281537ca", projects)
}

func singleFileApplications(inputs []applicationInput, cases []applicationCase) ([]applicationProject, error) {
	var projects []applicationProject
	seen := map[string]bool{}
	for _, input := range inputs {
		if seen[input.file] {
			return nil, fmt.Errorf("duplicate input %s", input.file)
		}
		seen[input.file] = true
		p := applicationProject{inputs: []applicationInput{input}}
		for _, c := range cases {
			if c.file == input.file {
				p.cases = append(p.cases, c)
			}
		}
		projects = append(projects, p)
	}
	for _, c := range cases {
		if !seen[c.file] {
			return nil, fmt.Errorf("label has no input %s", c.file)
		}
	}
	return projects, nil
}
