package lifecycle

import (
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/runrecord"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Evidence struct {
	Engine        string `json:"engine"`
	Configuration string `json:"configuration"`
	Scopes        string `json:"scopes"`
	Complete      bool   `json:"complete"`
	FileObserved  bool   `json:"file_observed"`
}
type Entry struct {
	Evidence           Evidence        `json:"evidence"`
	PreviouslyResolved bool            `json:"previously_resolved"`
	Key                string          `json:"key"`
	Finding            finding.Finding `json:"finding"`
	State              string          `json:"state"`
	Owner              string          `json:"owner,omitempty"`
	Due                string          `json:"due,omitempty"`
	Overdue            bool            `json:"overdue"`
}
type Registry struct {
	EvaluatedOn string           `json:"evaluated_on,omitempty"`
	Version     int              `json:"version"`
	Previous    runrecord.Record `json:"previous"`
	Entries     []Entry          `json:"entries"`
}

func Comparable(a, b runrecord.Record) bool {
	return a.Version == 1 && b.Version == 1 && a.Engine == b.Engine && a.Configuration == b.Configuration && len(a.Scopes) > 0 && runrecord.Digest(a.Scopes) == runrecord.Digest(b.Scopes) && a.Scopes[0].Complete && b.Scopes[0].Complete
}
func Step(old Registry, current runrecord.Record) Registry {
	if old.Version == 1 && runrecord.Digest(old.Previous) == runrecord.Digest(current) {
		return old
	}
	entries := map[string]Entry{}
	for _, e := range old.Entries {
		entries[e.Key] = e
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, f := range current.Report.Findings {
		if baseline.Incomplete(f) {
			continue
		}
		id := baseline.Key(f)
		counts[id]++
		key := id + ":" + strconv.Itoa(counts[id])
		e, exists := entries[key]
		if !exists {
			e = Entry{Key: key, State: "new"}
		} else if e.State == "resolved" || e.PreviouslyResolved {
			e.State = "reopened"
		} else {
			e.State = "active"
		}
		e.PreviouslyResolved = false
		e.Finding = f
		e.Evidence = Evidence{Engine: current.Engine, Configuration: current.Configuration, Scopes: runrecord.Digest(current.Scopes), Complete: len(current.Scopes) > 0 && current.Scopes[0].Complete}
		if f.Location != nil {
			e.Evidence.FileObserved = slices.Contains(current.Files, f.Location.File)
		}
		entries[key] = e
		seen[key] = true
	}
	for key, e := range entries {
		if !seen[key] {
			e.State = "unobserved"
			if e.Evidence.Complete && e.Evidence.FileObserved && e.Evidence.Engine == current.Engine && e.Evidence.Configuration == current.Configuration && e.Evidence.Scopes == runrecord.Digest(current.Scopes) && len(current.Scopes) > 0 && current.Scopes[0].Complete && strings.HasPrefix(e.Finding.ID, "sast:") && e.Finding.Location != nil && slices.Contains(current.Files, e.Finding.Location.File) {
				e.State = "resolved"
				e.Overdue = false
				e.PreviouslyResolved = true
			}
			entries[key] = e
		}
	}
	out := Registry{Version: 1, EvaluatedOn: old.EvaluatedOn, Previous: current, Entries: []Entry{}}
	for _, e := range entries {
		out.Entries = append(out.Entries, e)
	}
	slices.SortFunc(out.Entries, func(a, b Entry) int { return strings.Compare(a.Key, b.Key) })
	Age(&out, old.EvaluatedOn)
	return out
}
func Assign(r *Registry, key, owner, due string) error {
	if due != "" {
		if _, e := time.Parse("2006-01-02", due); e != nil {
			return fmt.Errorf("due date must be YYYY-MM-DD")
		}
	}
	for i := range r.Entries {
		if r.Entries[i].Key == key {
			r.Entries[i].Owner = owner
			r.Entries[i].Due = due
			r.Entries[i].Overdue = false
			Age(r, r.EvaluatedOn)
			return nil
		}
	}
	return fmt.Errorf("finding key not found")
}
func Age(r *Registry, asOf string) error {
	if asOf == "" {
		return nil
	}
	if _, e := time.Parse("2006-01-02", asOf); e != nil {
		return fmt.Errorf("as-of date must be YYYY-MM-DD")
	}
	r.EvaluatedOn = asOf
	for i := range r.Entries {
		e := &r.Entries[i]
		e.Overdue = e.State != "resolved" && e.Due != "" && e.Due < asOf
	}
	return nil
}
