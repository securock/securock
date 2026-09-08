package verify

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

type Finding struct {
	Identity string
	Reason   string
}

type Result struct {
	Findings []Finding
}

func (r Result) Error() string {
	if len(r.Findings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Identity == "" {
			parts = append(parts, f.Reason)
			continue
		}
		parts = append(parts, f.Identity+": "+f.Reason)
	}
	return strings.Join(parts, "\n")
}

func Compare(locked, current lockfile.Document) Result {
	var findings []Finding

	lockedBySubject := groupBySubject(locked.Artifacts)
	currentBySubject := groupBySubject(current.Artifacts)

	for id, arts := range currentBySubject {
		prev, ok := lockedBySubject[id]
		if !ok {
			findings = append(findings, Finding{Identity: id, Reason: "not present in securock.lock"})
			continue
		}
		if digestChanged(prev, arts) {
			findings = append(findings, Finding{Identity: id, Reason: "digest mismatch"})
		}
		for _, art := range arts {
			if art.Trust.Status == lockfile.StatusUntrusted {
				findings = append(findings, Finding{
					Identity: id,
					Reason:   "untrusted (" + strings.Join(art.Trust.Reasons, ", ") + ")",
				})
			}
		}
	}

	for id := range lockedBySubject {
		if _, ok := currentBySubject[id]; !ok {
			findings = append(findings, Finding{Identity: id, Reason: "missing from current dependencies"})
		}
	}

	slices.SortFunc(findings, func(a, b Finding) int {
		if n := cmp.Compare(a.Identity, b.Identity); n != 0 {
			return n
		}
		return cmp.Compare(a.Reason, b.Reason)
	})

	return Result{Findings: findings}
}

func groupBySubject(arts []lockfile.Artifact) map[string][]lockfile.Artifact {
	out := make(map[string][]lockfile.Artifact)
	for _, art := range arts {
		id := art.SubjectID()
		out[id] = append(out[id], art)
	}
	return out
}

func digestChanged(locked, current []lockfile.Artifact) bool {
	prev := digests(locked)
	got := digests(current)
	if len(prev) != len(got) {
		return true
	}
	for i := range prev {
		if prev[i] != got[i] {
			return true
		}
	}
	return false
}

func digests(arts []lockfile.Artifact) []string {
	out := make([]string, 0, len(arts))
	for _, art := range arts {
		if art.Digest != "" {
			out = append(out, art.Digest)
		}
	}
	slices.Sort(out)
	return out
}

func Failed(r Result) error {
	if len(r.Findings) == 0 {
		return nil
	}
	return fmt.Errorf("verify failed:\n%s", r.Error())
}
