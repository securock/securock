package coverage

import (
	"github.com/securock/securock/internal/finding"
	"net/url"
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
			if targetContains(target, f.Subject) && isGap(f.ID) {
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
		if isGap(f.ID) {
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
	for _, f := range out.Gaps {
		if strings.HasPrefix(f.ID, "sast:") {
			out.Scopes[0].State = "incomplete"
		}
	}
	slices.SortFunc(out.Scopes, func(a, b Scope) int { return strings.Compare(a.Kind+a.Target, b.Kind+b.Target) })
	return out
}

// Keep unsupported resources in the evidence-gap summary even when a scanner
// can still return useful results for the rest of the inventory.
func isGap(id string) bool {
	for _, marker := range []string{"incomplete", "unchecked", "unavailable", "unsupported"} {
		if strings.Contains(id, marker) {
			return true
		}
	}
	return false
}

func targetContains(target, subject string) bool {
	a, e := url.Parse(target)
	if e != nil {
		return false
	}
	b, e := url.Parse(subject)
	if e != nil || !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Host, b.Host) {
		return false
	}
	prefix := strings.TrimRight(a.Path, "/")
	return b.Path == prefix || strings.HasPrefix(b.Path, prefix+"/")
}
