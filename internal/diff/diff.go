package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

type Side struct {
	Versions    []string               `json:"versions,omitempty"`
	Digests     []string               `json:"digests,omitempty"`
	Provenance  lockfile.EvidenceState `json:"provenance,omitempty"`
	Signature   lockfile.EvidenceState `json:"signature,omitempty"`
	VulnState   lockfile.VulnState     `json:"vuln_state,omitempty"`
	Vulns       []string               `json:"vulnerabilities,omitempty"`
	Trust       lockfile.Status        `json:"trust,omitempty"`
	TrustReason []string               `json:"reasons,omitempty"`
}

type Change struct {
	Artifact string `json:"artifact"`
	Subject  string `json:"subject"`
	Before   Side   `json:"before"`
	After    Side   `json:"after"`
}

type Result struct {
	Changes      []Change
	Added        []string
	Removed      []string
	PolicyBefore string
	PolicyAfter  string
}

func Compare(locked, current lockfile.Document) Result {
	result := Result{
		PolicyBefore: locked.Policy.Digest,
		PolicyAfter:  current.Policy.Digest,
	}
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

	for _, id := range ids {
		prev, hadPrev := before[id]
		next, hadNext := after[id]
		switch {
		case !hadPrev:
			result.Added = append(result.Added, id)
		case !hadNext:
			result.Removed = append(result.Removed, id)
		case changed(prev, next):
			result.Changes = append(result.Changes, Change{
				Artifact: id,
				Subject:  subjectOf(id),
				Before:   prev,
				After:    next,
			})
		}
	}
	return result
}

func (r Result) TrustDrift() bool {
	if r.PolicyBefore != r.PolicyAfter {
		return true
	}
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
	if r.PolicyBefore != r.PolicyAfter {
		n++
	}
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

	if r.PolicyBefore != r.PolicyAfter {
		fmt.Fprintf(w, "\npolicy\n")
		writeField(w, "digest", r.PolicyBefore, r.PolicyAfter, false)
	}

	for _, id := range r.Removed {
		fmt.Fprintf(w, "\n%s\n  removed\n", id)
	}
	for _, id := range r.Added {
		fmt.Fprintf(w, "\n%s\n  added\n", id)
	}
	for _, c := range r.Changes {
		fmt.Fprintf(w, "\n%s\n", displayName(c.Artifact))
		writeField(w, "version", join(c.Before.Versions), join(c.After.Versions), false)
		writeDigest(w, c.Before.Digests, c.After.Digests)
		writeState(w, "provenance", c.Before.Provenance, c.After.Provenance)
		writeState(w, "signature", c.Before.Signature, c.After.Signature)
		writeField(w, "vuln state", string(c.Before.VulnState), string(c.After.VulnState), false)
		writeField(w, "vulnerabilities", ids(c.Before.Vulns), ids(c.After.Vulns), false)
		writeField(w, "trust", string(c.Before.Trust), string(c.After.Trust), false)
		writeField(w, "reason", join(c.Before.TrustReason), join(c.After.TrustReason), false)
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
		id := art.ArtifactID()
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
		for _, v := range art.Evidence.Vulnerabilities.Items {
			s.Vulns = append(s.Vulns, v.ID)
		}
		s.VulnState = worstVuln(s.VulnState, art.Evidence.Vulnerabilities.State)
		s.Provenance = worstEvidence(s.Provenance, art.Evidence.Provenance)
		s.Signature = worstEvidence(s.Signature, art.Evidence.Signature)
		s.Trust = worstTrust(s.Trust, art.Trust.Status)
		s.TrustReason = append(s.TrustReason, art.Trust.Reasons...)
	}
	slices.Sort(s.Versions)
	s.Versions = slices.Compact(s.Versions)
	slices.Sort(s.Digests)
	s.Digests = slices.Compact(s.Digests)
	slices.Sort(s.Vulns)
	s.Vulns = slices.Compact(s.Vulns)
	slices.Sort(s.TrustReason)
	s.TrustReason = slices.Compact(s.TrustReason)
	return s
}

func changed(a, b Side) bool {
	return join(a.Versions) != join(b.Versions) ||
		join(a.Digests) != join(b.Digests) ||
		a.Provenance != b.Provenance ||
		a.Signature != b.Signature ||
		a.VulnState != b.VulnState ||
		join(a.Vulns) != join(b.Vulns) ||
		a.Trust != b.Trust ||
		join(a.TrustReason) != join(b.TrustReason)
}

func trustRelevant(a, b Side) bool {
	return join(a.Versions) != join(b.Versions) ||
		join(a.Digests) != join(b.Digests) ||
		a.Provenance != b.Provenance ||
		a.Signature != b.Signature ||
		a.VulnState != b.VulnState ||
		join(a.Vulns) != join(b.Vulns) ||
		a.Trust != b.Trust ||
		join(a.TrustReason) != join(b.TrustReason)
}

func worstVuln(a, b lockfile.VulnState) lockfile.VulnState {
	if a == "" {
		return b
	}
	if a == lockfile.VulnUnknown || b == lockfile.VulnUnknown {
		return lockfile.VulnUnknown
	}
	return b
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

func displayName(artifactID string) string {
	_, name, ok := strings.Cut(artifactID, ":")
	if !ok || name == "" {
		return artifactID
	}
	return name
}

func subjectOf(artifactID string) string {
	id := artifactID
	if i := strings.Index(id, "#"); i >= 0 {
		id = id[:i]
	}
	if i := strings.LastIndex(id, "@"); i > 0 {
		return id[:i]
	}
	return artifactID
}

func join(in []string) string {
	cp := append([]string(nil), in...)
	slices.Sort(cp)
	return strings.Join(cp, ", ")
}

func ids(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return join(in)
}

type PolicyChange struct {
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type Report struct {
	SchemaVersion int           `json:"schema_version"`
	TrustDrift    bool          `json:"trust_drift"`
	Policy        *PolicyChange `json:"policy,omitempty"`
	Added         []string      `json:"added,omitempty"`
	Removed       []string      `json:"removed,omitempty"`
	Changes       []Change      `json:"changes,omitempty"`
}

func WriteJSON(w io.Writer, r Result) error {
	rep := Report{
		SchemaVersion: 1,
		TrustDrift:    r.TrustDrift(),
		Added:         r.Added,
		Removed:       r.Removed,
		Changes:       r.Changes,
	}
	if r.PolicyBefore != "" || r.PolicyAfter != "" {
		rep.Policy = &PolicyChange{Before: r.PolicyBefore, After: r.PolicyAfter}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
