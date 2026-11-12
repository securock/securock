package validation

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"io"
	"slices"
	"strings"
)

type Step struct {
	Name      string   `json:"name"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Expected  []string `json:"expected"`
	Forbidden []string `json:"forbidden"`
}
type Suite struct {
	Version int    `json:"version"`
	Steps   []Step `json:"steps"`
}
type Result struct {
	Name             string   `json:"name"`
	Passed           bool     `json:"passed"`
	OperationalError bool     `json:"operational_error"`
	Missing          []string `json:"missing"`
	Unexpected       []string `json:"unexpected"`
}
type Report struct {
	Version int      `json:"version"`
	Results []Result `json:"results"`
}

func Read(r io.Reader) (Suite, error) {
	var s Suite
	raw, e := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return s, fmt.Errorf("suite exceeds limit")
	}
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 || len(s.Steps) == 0 || len(s.Steps) > 100 {
		return s, fmt.Errorf("invalid validation suite")
	}
	seen := map[string]bool{}
	for _, step := range s.Steps {
		if step.Name == "" || seen[step.Name] || !slices.Contains([]string{"security", "dast", "cspm", "container"}, step.Command) {
			return s, fmt.Errorf("suite requires unique names and read-only scanner commands")
		}
		seen[step.Name] = true
		for _, arg := range step.Args {
			for _, flag := range []string{"--output", "--record", "--coverage-output"} {
				if arg == flag || strings.HasPrefix(arg, flag+"=") {
					return s, fmt.Errorf("suite cannot redirect or write scanner reports")
				}
			}
		}
	}
	return s, nil
}
func Evaluate(step Step, r finding.Report, err error) Result {
	out := Result{Name: step.Name, Passed: err == nil, OperationalError: err != nil, Missing: []string{}, Unexpected: []string{}}
	ids := map[string]bool{}
	for _, f := range r.Findings {
		ids[f.ID] = true
		if strings.Contains(f.ID, "analysis-incomplete") {
			out.OperationalError = true
			out.Passed = false
		}
	}
	for _, id := range step.Expected {
		if !ids[id] {
			out.Missing = append(out.Missing, id)
			out.Passed = false
		}
	}
	for _, id := range step.Forbidden {
		if ids[id] {
			out.Unexpected = append(out.Unexpected, id)
			out.Passed = false
		}
	}
	return out
}
