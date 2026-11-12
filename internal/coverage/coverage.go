package coverage

import (
	"github.com/securock/securock/internal/finding"
	"slices"
	"strings"
)

type Scope struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	State  string `json:"state"`
}
type Report struct {
	Version     int               `json:"version"`
	Scopes      []Scope           `json:"scopes"`
	Limitations []string          `json:"limitations"`
	Gaps        []finding.Finding `json:"gaps"`
}

func Build(report finding.Report, targets, files []string, region string) Report {
	out := Report{Version: 1, Scopes: []Scope{{Kind: "source", Target: "project", State: "attempted"}}, Limitations: []string{"Attempted scopes are not proof of exhaustive analysis or freshness."}, Gaps: []finding.Finding{}}
	for _, target := range targets {
		state := "attempted"
		for _, f := range report.Findings {
			if strings.HasPrefix(f.Subject, target) && strings.Contains(f.ID, "incomplete") {
				state = "incomplete"
			}
		}
		out.Scopes = append(out.Scopes, Scope{"dast", target, state})
	}
	for range files {
		out.Scopes = append(out.Scopes, Scope{"cspm-inventory", "local inventory", "recorded"})
	}
	if region != "" {
		out.Scopes = append(out.Scopes, Scope{"aws-config", region, "recorded"})
	}
	seen := map[string]bool{}
	for _, f := range report.Findings {
		if strings.Contains(f.ID, "incomplete") || strings.Contains(f.ID, "unchecked") || strings.Contains(f.ID, "unavailable") {
			out.Gaps = append(out.Gaps, f)
		}
		if strings.HasPrefix(f.Subject, "AWS::") {
			parts := strings.Split(f.Subject, "/")
			if len(parts) >= 4 {
				target := parts[1] + "/" + parts[2]
				if !seen[target] {
					seen[target] = true
					out.Scopes = append(out.Scopes, Scope{"aws-account-region", target, "recorded"})
				}
			}
		}
	}
	slices.SortFunc(out.Scopes, func(a, b Scope) int { return strings.Compare(a.Kind+a.Target, b.Kind+b.Target) })
	return out
}
