package diff

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

type Side struct {
	Versions    []string
	Digests     []string
	Provenance  lockfile.EvidenceState
	Signature   lockfile.EvidenceState
	Vulns       []string
	Trust       lockfile.Status
	TrustReason []string
}

type Change struct {
	Subject string
	Before  Side
	After   Side
}

type Result struct {
	Changes []Change
	Added   []string
	Removed []string
}

func Compare(locked, current lockfile.Document) Result {
	before := summarize(locked.Artifacts)
	after := summarize(current.Artifacts)

	subjects := make(map[string]struct{})
	for id := range before {
		subjects[id] = struct{}{}
	}
	for id := range after {
		subjects[id] = struct{}{}
	}

	ids := make([]string, 0, len(subjects))
	for id := range subjects {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var result Result
	for _, id := range ids {
		prev, hadPrev := before[id]
		next, hadNext := after[id]
		switch {
		case !hadPrev:
			result.Added = append(result.Added, id)
		case !hadNext:
			result.Removed = append(result.Removed, id)
		case changed(prev, next):
			result.Changes = append(result.Changes, Change{Subject: id, Before: prev, After: next})
		}
	}
	return result
}

func (r Result) TrustDrift() bool {
	if len(r.Added) > 0 || len(r.Removed) > 0 {
		return true
	}
	for _, c := range r.Changes {
		if trustRelevant(c.Before, c.After) {
			return true
		}
	}
	return false
}

func (r Result) TrustChanges() int {
	n := len(r.Added) + len(r.Removed)
	for _, c := range r.Changes {
		if trustRelevant(c.Before, c.After) {
			n++
		}
	}
	return n
}

func Write(w io.Writer, r Result) {
	n := r.TrustChanges()
	fmt.Fprintf(w, "%d trust change", n)
	if n != 1 {
		fmt.Fprint(w, "s")
	}
	fmt.Fprintln(w)

	for _, id := range r.Removed {
		fmt.Fprintf(w, "\n%s\n  removed\n", id)
	}
	for _, id := range r.Added {
		fmt.Fprintf(w, "\n%s\n  added\n", id)
	}
	for _, c := range r.Changes {
		fmt.Fprintf(w, "\n%s\n", displayName(c.Subject))
		writeField(w, "version", join(c.Before.Versions), join(c.After.Versions), false)
		writeDigest(w, c.Before.Digests, c.After.Digests)
		writeState(w, "provenance", c.Before.Provenance, c.After.Provenance)
		writeState(w, "signature", c.Before.Signature, c.After.Signature)
		fmt.Fprintf(w, "  %-14s%d → %d\n", "vulnerabilities", len(c.Before.Vulns), len(c.After.Vulns))
		writeField(w, "trust", string(c.Before.Trust), string(c.After.Trust), false)
	}

	if r.TrustDrift() {
		fmt.Fprintln(w, "\nTrust drift detected.")
		return
	}
	fmt.Fprintln(w, "\nNo trust drift.")
}

func summarize(arts []lockfile.Artifact) map[string]Side {
	grouped := make(map[string][]lockfile.Artifact)
	for _, art := range arts {
		id := art.SubjectID()
		grouped[id] = append(grouped[id], art)
	}
	out := make(map[string]Side, len(grouped))
	for id, group := range grouped {
		out[id] = sideOf(group)
	}
	return out
}

func sideOf(arts []lockfile.Artifact) Side {
	s := Side{
		Trust:      lockfile.StatusTrusted,
		Provenance: lockfile.EvidenceUnknown,
		Signature:  lockfile.EvidenceUnknown,
	}
	if len(arts) == 0 {
		return s
	}
	s.Provenance = arts[0].Evidence.Provenance
	s.Signature = arts[0].Evidence.Signature
	s.Trust = arts[0].Trust.Status
	for _, art := range arts {
		s.Versions = append(s.Versions, art.Version)
		if art.Digest != "" {
			s.Digests = append(s.Digests, art.Digest)
		}
		for _, v := range art.Evidence.Vulnerabilities {
			s.Vulns = append(s.Vulns, v.ID)
		}
		s.Provenance = worstEvidence(s.Provenance, art.Evidence.Provenance)
		s.Signature = worstEvidence(s.Signature, art.Evidence.Signature)
		s.Trust = worstTrust(s.Trust, art.Trust.Status)
	}
	slices.Sort(s.Versions)
	s.Versions = slices.Compact(s.Versions)
	slices.Sort(s.Digests)
	s.Digests = slices.Compact(s.Digests)
	slices.Sort(s.Vulns)
	s.Vulns = slices.Compact(s.Vulns)
	return s
}

func changed(a, b Side) bool {
	return join(a.Versions) != join(b.Versions) ||
		join(a.Digests) != join(b.Digests) ||
		a.Provenance != b.Provenance ||
		a.Signature != b.Signature ||
		len(a.Vulns) != len(b.Vulns) ||
		a.Trust != b.Trust
}

func trustRelevant(a, b Side) bool {
	return join(a.Digests) != join(b.Digests) ||
		a.Provenance != b.Provenance ||
		a.Signature != b.Signature ||
		len(a.Vulns) != len(b.Vulns) ||
		a.Trust != b.Trust
}

func worstEvidence(a, b lockfile.EvidenceState) lockfile.EvidenceState {
	order := map[lockfile.EvidenceState]int{
		lockfile.EvidenceVerified: 0,
		lockfile.EvidencePresent:  1,
		lockfile.EvidenceUnknown:  2,
		lockfile.EvidenceMissing:  3,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}

func worstTrust(a, b lockfile.Status) lockfile.Status {
	order := map[lockfile.Status]int{
		lockfile.StatusTrusted:   0,
		lockfile.StatusUnknown:   1,
		lockfile.StatusUntrusted: 2,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}

func writeField(w io.Writer, name, before, after string, always bool) {
	if before == after && !always {
		return
	}
	if before == after {
		fmt.Fprintf(w, "  %-14s%s\n", name, after)
		return
	}
	fmt.Fprintf(w, "  %-14s%s → %s\n", name, before, after)
}

func writeDigest(w io.Writer, before, after []string) {
	if join(before) == join(after) {
		return
	}
	fmt.Fprintf(w, "  %-14s%s\n", "digest", "changed")
}

func writeState(w io.Writer, name string, before, after lockfile.EvidenceState) {
	if before == after {
		if after != "" {
			fmt.Fprintf(w, "  %-14s%s\n", name, after)
		}
		return
	}
	fmt.Fprintf(w, "  %-14s%s → %s\n", name, before, after)
}

func displayName(subjectID string) string {
	_, name, ok := strings.Cut(subjectID, ":")
	if !ok || name == "" {
		return subjectID
	}
	return name
}

func join(in []string) string {
	slices.Sort(in)
	return strings.Join(in, ", ")
}
