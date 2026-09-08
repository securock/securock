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

	lockedByID := make(map[string]lockfile.Artifact, len(locked.Artifacts))
	for _, art := range locked.Artifacts {
		lockedByID[art.Identity()] = art
	}
	currentByID := make(map[string]lockfile.Artifact, len(current.Artifacts))
	for _, art := range current.Artifacts {
		currentByID[art.Identity()] = art
	}

	for id, art := range currentByID {
		prev, ok := lockedByID[id]
		if !ok {
			findings = append(findings, Finding{Identity: id, Reason: "not present in securock.lock"})
			continue
		}
		if prev.Digest != "" && art.Digest != "" && prev.Digest != art.Digest {
			findings = append(findings, Finding{Identity: id, Reason: "digest mismatch"})
		}
		if art.Trust.Status == lockfile.StatusUntrusted {
			findings = append(findings, Finding{
				Identity: id,
				Reason:   "untrusted (" + strings.Join(art.Trust.Reasons, ", ") + ")",
			})
		}
	}

	for id := range lockedByID {
		if _, ok := currentByID[id]; !ok {
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

func Failed(r Result) error {
	if len(r.Findings) == 0 {
		return nil
	}
	return fmt.Errorf("verify failed:\n%s", r.Error())
}
