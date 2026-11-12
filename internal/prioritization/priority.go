package prioritization

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"io"
	"slices"
	"strings"
)

type Asset struct {
	Match       string   `json:"match"`
	Owner       string   `json:"owner,omitempty"`
	Criticality int      `json:"criticality"`
	Internet    *bool    `json:"internet_exposed,omitempty"`
	Reachable   *bool    `json:"reachable,omitempty"`
	Privileged  *bool    `json:"privileged,omitempty"`
	Exploited   *bool    `json:"known_exploited,omitempty"`
	Evidence    []string `json:"evidence"`
}
type Context struct {
	Version int     `json:"version"`
	Assets  []Asset `json:"assets"`
}
type Item struct {
	Key      string          `json:"key"`
	Score    int             `json:"score"`
	Owner    string          `json:"owner,omitempty"`
	Reasons  []string        `json:"reasons"`
	Evidence []string        `json:"evidence"`
	Finding  finding.Finding `json:"finding"`
}
type Report struct {
	Version    int    `json:"version"`
	Limitation string `json:"limitation"`
	Items      []Item `json:"items"`
}

func Read(r io.Reader) (Context, error) {
	var c Context
	raw, e := io.ReadAll(io.LimitReader(r, 2<<20+1))
	if e != nil || len(raw) > 2<<20 {
		return c, fmt.Errorf("asset context exceeds limit")
	}
	if json.Unmarshal(raw, &c) != nil || c.Version != 1 {
		return c, fmt.Errorf("invalid asset context")
	}
	seen := map[string]bool{}
	for _, a := range c.Assets {
		if a.Match == "" || seen[a.Match] || a.Criticality < 1 || a.Criticality > 5 || len(a.Evidence) == 0 {
			return c, fmt.Errorf("assets require unique match, criticality 1..5, and evidence references")
		}
		seen[a.Match] = true
	}
	return c, nil
}
func Rank(r finding.Report, c Context) Report {
	out := Report{Version: 1, Limitation: "Scores use declared context, not independently verified reachability or effective permissions. Original severity is unchanged.", Items: []Item{}}
	for _, f := range r.Findings {
		item := Item{Key: baseline.Key(f), Score: (f.Severity.Rank() + 1) * 10, Finding: f, Reasons: []string{"original severity: " + string(f.Severity)}, Evidence: []string{}}
		var match *Asset
		for i := range c.Assets {
			a := &c.Assets[i]
			if strings.HasPrefix(f.Subject, a.Match) && (match == nil || len(a.Match) > len(match.Match)) {
				match = a
			}
		}
		if match != nil {
			item.Owner = match.Owner
			item.Score += match.Criticality * 3
			item.Reasons = append(item.Reasons, fmt.Sprintf("declared asset criticality: %d", match.Criticality))
			item.Evidence = match.Evidence
			for _, signal := range []struct {
				v      *bool
				name   string
				weight int
			}{{match.Internet, "internet exposure", 10}, {match.Reachable, "reachable", 10}, {match.Privileged, "privileged", 10}, {match.Exploited, "known exploitation", 15}} {
				if signal.v == nil {
					item.Reasons = append(item.Reasons, signal.name+": unknown")
				} else if *signal.v {
					item.Score += signal.weight
					item.Reasons = append(item.Reasons, "declared "+signal.name)
				}
			}
		} else {
			item.Reasons = append(item.Reasons, "asset context: unknown")
		}
		if f.Suppressed != nil {
			item.Score = 0
			item.Reasons = append(item.Reasons, "accepted finding; excluded from actionable priority")
		}
		out.Items = append(out.Items, item)
	}
	slices.SortStableFunc(out.Items, func(a, b Item) int {
		if a.Score != b.Score {
			return b.Score - a.Score
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out
}
