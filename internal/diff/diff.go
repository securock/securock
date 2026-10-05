package diff

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

type Side struct {
	Versions       []string                    `json:"versions,omitempty"`
	Digests        []string                    `json:"digests,omitempty"`
	Provenance     lockfile.EvidenceState      `json:"provenance,omitempty"`
	Signature      lockfile.EvidenceState      `json:"signature,omitempty"`
	VulnState      lockfile.VulnState          `json:"vuln_state,omitempty"`
	Vulns          []string                    `json:"vulnerabilities,omitempty"`
	MaliciousState lockfile.VulnState          `json:"malicious_state,omitempty"`
	Malicious      []string                    `json:"malicious,omitempty"`
	Trust          lockfile.Status             `json:"trust,omitempty"`
	TrustReason    []string                    `json:"reasons,omitempty"`
	Kinds          []string                    `json:"kinds,omitempty"`
	Registries     []string                    `json:"registries,omitempty"`
	Artifacts      []string                    `json:"artifacts,omitempty"`
	Requested      []string                    `json:"requested,omitempty"`
	Resolved       []string                    `json:"resolved,omitempty"`
	Capabilities   lockfile.CapabilityEvidence `json:"capabilities,omitempty"`
	Behavior       lockfile.BehaviorEvidence   `json:"behavior,omitempty"`
	Chain          lockfile.ChainEvidence      `json:"chain,omitempty"`
	Publisher      string                      `json:"publisher,omitempty"`
	Maintainers    []string                    `json:"maintainers,omitempty"`
	OwnershipState lockfile.CapState           `json:"ownership_state,omitempty"`
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
	Policy       policy.Document
}

func (r Result) WithPolicy(pol policy.Document) Result {
	r.Policy = pol
	return r
}

func Compare(locked, current lockfile.Document) Result {
	result := Result{
		PolicyBefore: locked.Policy.Digest,
		PolicyAfter:  current.Policy.Digest,
	}
	before := summarize(locked.Artifacts)
	after := summarize(current.Artifacts)

	keys := make([]artifactKey, 0, len(before)+len(after))
	seen := map[artifactKey]struct{}{}
	for k := range before {
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range after {
		if _, ok := seen[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b artifactKey) int {
		return cmp.Compare(a.id(), b.id())
	})

	for _, k := range keys {
		prev, hadPrev := before[k]
		next, hadNext := after[k]
		switch {
		case !hadPrev:
			result.Added = append(result.Added, k.id())
		case !hadNext:
			result.Removed = append(result.Removed, k.id())
		case changed(prev, next):
			result.Changes = append(result.Changes, Change{
				Artifact: k.id(),
				Subject:  k.subject(),
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
		if trustRelevant(c.Before, c.After, r.Policy) {
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
		if trustRelevant(c.Before, c.After, r.Policy) {
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
		writeField(w, "malicious state", string(c.Before.MaliciousState), string(c.After.MaliciousState), false)
		writeField(w, "malicious", ids(c.Before.Malicious), ids(c.After.Malicious), false)
		writeField(w, "trust", string(c.Before.Trust), string(c.After.Trust), false)
		writeField(w, "reason", join(c.Before.TrustReason), join(c.After.TrustReason), false)
		writeField(w, "kind", join(c.Before.Kinds), join(c.After.Kinds), false)
		writeField(w, "registry", join(c.Before.Registries), join(c.After.Registries), false)
		writeField(w, "artifact", join(c.Before.Artifacts), join(c.After.Artifacts), false)
		writeField(w, "requested", join(c.Before.Requested), join(c.After.Requested), false)
		writeField(w, "resolved", join(c.Before.Resolved), join(c.After.Resolved), false)
		writeCapabilities(w, c.Before.Capabilities, c.After.Capabilities)
		writeBehavior(w, c.Before.Behavior, c.After.Behavior)
		writeChain(w, c.Before.Chain, c.After.Chain)
		writeOwnership(w, c.Before, c.After)
		writeOwnershipPolicy(w, c.Before, c.After, r.Policy.Rules.Ownership)
	}

	if r.TrustDrift() {
		fmt.Fprintln(w, "\nTrust drift detected.")
		return
	}
	fmt.Fprintln(w, "\nNo trust drift.")
}

func summarize(arts []lockfile.Artifact) map[artifactKey]Side {
	grouped := make(map[artifactKey][]lockfile.Artifact)
	for _, art := range arts {
		k := keyOf(art)
		grouped[k] = append(grouped[k], art)
	}
	out := make(map[artifactKey]Side, len(grouped))
	for k, group := range grouped {
		out[k] = sideOf(group)
	}
	return out
}

func sideOf(arts []lockfile.Artifact) Side {
	s := Side{
		Trust:      lockfile.StatusTrusted,
		Provenance: lockfile.EvidenceUnknown,
		Signature:  lockfile.EvidenceUnknown,
		Capabilities: lockfile.CapabilityEvidence{
			State: lockfile.CapUnknown,
		},
		Behavior: lockfile.BehaviorEvidence{
			State: lockfile.CapUnknown,
		},
		Chain: lockfile.ChainEvidence{
			State: lockfile.EvidenceUnknown,
		},
		OwnershipState: lockfile.CapUnknown,
	}
	if len(arts) == 0 {
		return s
	}
	s.Provenance = arts[0].Evidence.Provenance
	s.Signature = arts[0].Evidence.Signature
	s.Trust = arts[0].Trust.Status
	s.Capabilities = arts[0].Evidence.Capabilities
	s.Behavior = arts[0].Evidence.Behavior
	s.Chain = arts[0].Evidence.Chain
	s.OwnershipState = arts[0].Evidence.Ownership.State
	var publishers []string
	for _, art := range arts {
		if art.Version != "" {
			s.Versions = append(s.Versions, art.Version)
		}
		if art.Digest != "" {
			s.Digests = append(s.Digests, art.Digest)
		}
		for _, v := range art.Evidence.Vulnerabilities.Items {
			s.Vulns = append(s.Vulns, v.ID)
		}
		for _, r := range art.Evidence.Malicious.Reports {
			s.Malicious = append(s.Malicious, r.ID)
		}
		s.VulnState = worstVuln(s.VulnState, art.Evidence.Vulnerabilities.State)
		s.MaliciousState = worstVuln(s.MaliciousState, art.Evidence.Malicious.State)
		s.Provenance = worstEvidence(s.Provenance, art.Evidence.Provenance)
		s.Signature = worstEvidence(s.Signature, art.Evidence.Signature)
		s.Trust = worstTrust(s.Trust, art.Trust.Status)
		s.TrustReason = append(s.TrustReason, art.Trust.Reasons...)
		s.Capabilities = mergeCapabilities(s.Capabilities, art.Evidence.Capabilities)
		s.Behavior = mergeBehavior(s.Behavior, art.Evidence.Behavior)
		s.Chain = mergeChain(s.Chain, art.Evidence.Chain)
		s.OwnershipState = worstCap(s.OwnershipState, art.Evidence.Ownership.State)
		if art.Evidence.Ownership.Publisher != "" {
			publishers = append(publishers, art.Evidence.Ownership.Publisher)
		}
		s.Maintainers = append(s.Maintainers, art.Evidence.Ownership.Maintainers...)
		if art.Source.Kind != "" {
			s.Kinds = append(s.Kinds, art.Source.Kind)
		}
		if art.Source.Registry != "" {
			s.Registries = append(s.Registries, art.Source.Registry)
		}
		if art.Source.Artifact != "" {
			s.Artifacts = append(s.Artifacts, art.Source.Artifact)
		}
		if art.Source.Requested != "" {
			s.Requested = append(s.Requested, art.Source.Requested)
		}
		if art.Source.Resolved != "" {
			s.Resolved = append(s.Resolved, art.Source.Resolved)
		}
	}
	slices.Sort(publishers)
	publishers = slices.Compact(publishers)
	s.Publisher = strings.Join(publishers, ", ")
	slices.Sort(s.Versions)
	s.Versions = slices.Compact(s.Versions)
	slices.Sort(s.Digests)
	s.Digests = slices.Compact(s.Digests)
	slices.Sort(s.Vulns)
	s.Vulns = slices.Compact(s.Vulns)
	slices.Sort(s.Malicious)
	s.Malicious = slices.Compact(s.Malicious)
	slices.Sort(s.TrustReason)
	s.TrustReason = slices.Compact(s.TrustReason)
	slices.Sort(s.Maintainers)
	s.Maintainers = slices.Compact(s.Maintainers)
	slices.Sort(s.Requested)
	s.Requested = slices.Compact(s.Requested)
	slices.Sort(s.Resolved)
	s.Resolved = slices.Compact(s.Resolved)
	slices.Sort(s.Kinds)
	s.Kinds = slices.Compact(s.Kinds)
	slices.Sort(s.Registries)
	s.Registries = slices.Compact(s.Registries)
	slices.Sort(s.Artifacts)
	s.Artifacts = slices.Compact(s.Artifacts)
	return s
}

func changed(a, b Side) bool {
	return nonOwnershipChanged(a, b) || ownershipChanged(a, b)
}

func nonOwnershipChanged(a, b Side) bool {
	return join(a.Versions) != join(b.Versions) ||
		join(a.Digests) != join(b.Digests) ||
		a.Provenance != b.Provenance ||
		a.Signature != b.Signature ||
		a.VulnState != b.VulnState ||
		join(a.Vulns) != join(b.Vulns) ||
		a.MaliciousState != b.MaliciousState ||
		join(a.Malicious) != join(b.Malicious) ||
		a.Trust != b.Trust ||
		join(a.TrustReason) != join(b.TrustReason) ||
		sourceChanged(a, b) ||
		!capabilitiesEqual(a.Capabilities, b.Capabilities) ||
		!behaviorEqual(a.Behavior, b.Behavior) ||
		!chainEqual(a.Chain, b.Chain)
}

func ownershipChanged(a, b Side) bool {
	return a.OwnershipState != b.OwnershipState ||
		a.Publisher != b.Publisher ||
		join(a.Maintainers) != join(b.Maintainers)
}

func trustRelevant(a, b Side, pol policy.Document) bool {
	if nonOwnershipChanged(a, b) {
		return true
	}
	if !ownershipChanged(a, b) {
		return false
	}
	return ownershipFails(a, b, pol.Rules.Ownership)
}

func ownershipFails(a, b Side, rule policy.OwnershipRule) bool {
	if !rule.Configured() {
		return true
	}
	if a.Publisher != b.Publisher {
		action := rule.PublisherChange
		if action == "" {
			action = policy.ActionDeny
		}
		if action.Fails() {
			return true
		}
	}
	removed, added := listDelta(a.Maintainers, b.Maintainers)
	if len(added) > 0 {
		action := rule.MaintainerAdded
		if action == "" {
			action = policy.ActionDeny
		}
		if action.Fails() {
			return true
		}
	}
	if len(removed) > 0 {
		action := rule.MaintainerRemoved
		if action == "" {
			action = policy.ActionDeny
		}
		if action.Fails() {
			return true
		}
	}
	if a.OwnershipState != b.OwnershipState {
		return true
	}
	return false
}

func writeOwnershipPolicy(w io.Writer, before, after Side, rule policy.OwnershipRule) {
	if !rule.Configured() || !ownershipChanged(before, after) {
		return
	}
	if before.Publisher != after.Publisher {
		action := rule.PublisherChange
		if action == "" {
			action = policy.ActionDeny
		}
		if action.Reports() {
			fmt.Fprintf(w, "  ownership violation: publisher changed (%s)\n", action)
		}
	}
	removed, added := listDelta(before.Maintainers, after.Maintainers)
	if len(added) > 0 {
		action := rule.MaintainerAdded
		if action == "" {
			action = policy.ActionDeny
		}
		if action.Reports() {
			fmt.Fprintf(w, "  ownership violation: maintainer added (%s)\n", action)
		}
	}
	if len(removed) > 0 {
		action := rule.MaintainerRemoved
		if action == "" {
			action = policy.ActionDeny
		}
		if action.Reports() {
			fmt.Fprintf(w, "  ownership violation: maintainer removed (%s)\n", action)
		}
	}
}

func sourceChanged(a, b Side) bool {
	return join(a.Kinds) != join(b.Kinds) ||
		join(a.Registries) != join(b.Registries) ||
		join(a.Artifacts) != join(b.Artifacts) ||
		join(a.Requested) != join(b.Requested) ||
		join(a.Resolved) != join(b.Resolved)
}

func behaviorEqual(a, b lockfile.BehaviorEvidence) bool {
	return a.State == b.State &&
		join(a.Network) == join(b.Network) &&
		join(behaviorFiles(a).Read) == join(behaviorFiles(b).Read) &&
		join(behaviorFiles(a).Write) == join(behaviorFiles(b).Write) &&
		join(a.Commands) == join(b.Commands) &&
		join(a.Environment) == join(b.Environment)
}

func behaviorFiles(b lockfile.BehaviorEvidence) lockfile.BehaviorFiles {
	if b.Files == nil {
		return lockfile.BehaviorFiles{}
	}
	return *b.Files
}

func mergeBehavior(a, b lockfile.BehaviorEvidence) lockfile.BehaviorEvidence {
	out := a
	out.State = worstCap(a.State, b.State)
	out.Network = append(slices.Clone(out.Network), b.Network...)
	read := append(slices.Clone(behaviorFiles(a).Read), behaviorFiles(b).Read...)
	write := append(slices.Clone(behaviorFiles(a).Write), behaviorFiles(b).Write...)
	out.Commands = append(slices.Clone(out.Commands), b.Commands...)
	out.Environment = append(slices.Clone(out.Environment), b.Environment...)
	slices.Sort(out.Network)
	out.Network = slices.Compact(out.Network)
	slices.Sort(read)
	read = slices.Compact(read)
	slices.Sort(write)
	write = slices.Compact(write)
	slices.Sort(out.Commands)
	out.Commands = slices.Compact(out.Commands)
	slices.Sort(out.Environment)
	out.Environment = slices.Compact(out.Environment)
	if len(read) > 0 || len(write) > 0 {
		out.Files = &lockfile.BehaviorFiles{Read: read, Write: write}
	} else {
		out.Files = nil
	}
	return out
}

func writeBehavior(w io.Writer, before, after lockfile.BehaviorEvidence) {
	if behaviorEqual(before, after) {
		return
	}
	fmt.Fprintln(w, "  behavior drift")
	writeListDelta(w, "network", before.Network, after.Network)
	writeListDelta(w, "filesystem read", behaviorFiles(before).Read, behaviorFiles(after).Read)
	writeListDelta(w, "filesystem write", behaviorFiles(before).Write, behaviorFiles(after).Write)
	writeListDelta(w, "commands", before.Commands, after.Commands)
	writeListDelta(w, "environment", before.Environment, after.Environment)
	if before.State != after.State {
		fmt.Fprintf(w, "    state          %s → %s\n", before.State, after.State)
	}
}

func chainEqual(a, b lockfile.ChainEvidence) bool {
	return a.State == b.State &&
		a.Source == b.Source &&
		a.Commit == b.Commit &&
		a.Builder == b.Builder &&
		a.Workflow == b.Workflow
}

func mergeChain(a, b lockfile.ChainEvidence) lockfile.ChainEvidence {
	out := a
	out.State = worstEvidence(a.State, b.State)
	if out.Source == "" {
		out.Source = b.Source
	}
	if out.Commit == "" {
		out.Commit = b.Commit
	}
	if out.Builder == "" {
		out.Builder = b.Builder
	}
	if out.Workflow == "" {
		out.Workflow = b.Workflow
	}
	return out
}

func writeChain(w io.Writer, before, after lockfile.ChainEvidence) {
	if chainEqual(before, after) {
		return
	}
	fmt.Fprintln(w, "  trust chain")
	writeField(w, "source", before.Source, after.Source, false)
	writeField(w, "commit", before.Commit, after.Commit, false)
	writeField(w, "builder", before.Builder, after.Builder, false)
	writeField(w, "workflow", before.Workflow, after.Workflow, false)
	if before.State != after.State {
		fmt.Fprintf(w, "    state          %s → %s\n", before.State, after.State)
	}
}

func writeListDelta(w io.Writer, name string, before, after []string) {
	removed, added := listDelta(before, after)
	if len(removed) == 0 && len(added) == 0 {
		return
	}
	fmt.Fprintf(w, "    %s:\n", name)
	for _, v := range removed {
		fmt.Fprintf(w, "      - %s\n", v)
	}
	for _, v := range added {
		fmt.Fprintf(w, "      + %s\n", v)
	}
}

func capabilitiesEqual(a, b lockfile.CapabilityEvidence) bool {
	return a.State == b.State &&
		boolPtrEqual(a.Network, b.Network) &&
		a.Filesystem == b.Filesystem &&
		boolPtrEqual(a.Environment, b.Environment) &&
		boolPtrEqual(a.Shell, b.Shell) &&
		boolPtrEqual(a.NativeCode, b.NativeCode) &&
		boolPtrEqual(a.InstallScripts, b.InstallScripts)
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func mergeCapabilities(a, b lockfile.CapabilityEvidence) lockfile.CapabilityEvidence {
	out := a
	out.State = worstCap(a.State, b.State)
	out.Network = orBool(a.Network, b.Network)
	out.Environment = orBool(a.Environment, b.Environment)
	out.Shell = orBool(a.Shell, b.Shell)
	out.NativeCode = orBool(a.NativeCode, b.NativeCode)
	out.InstallScripts = orBool(a.InstallScripts, b.InstallScripts)
	out.Filesystem = worstFilesystem(a.Filesystem, b.Filesystem)
	return out
}

func orBool(a, b *bool) *bool {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return lockfile.Bool(*a || *b)
}

func worstFilesystem(a, b lockfile.FilesystemAccess) lockfile.FilesystemAccess {
	order := map[lockfile.FilesystemAccess]int{
		"":                       0,
		lockfile.FilesystemNone:  1,
		lockfile.FilesystemRead:  2,
		lockfile.FilesystemWrite: 3,
	}
	if order[b] > order[a] {
		return b
	}
	return a
}

func worstCap(a, b lockfile.CapState) lockfile.CapState {
	if a == "" {
		return b
	}
	if a == lockfile.CapUnknown || b == lockfile.CapUnknown {
		return lockfile.CapUnknown
	}
	return lockfile.CapChecked
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

func writeCapabilities(w io.Writer, before, after lockfile.CapabilityEvidence) {
	if capabilitiesEqual(before, after) {
		return
	}
	fmt.Fprintln(w, "  capabilities changed:")
	writeCapBool(w, "network", before.Network, after.Network)
	writeCapFS(w, before.Filesystem, after.Filesystem)
	writeCapBool(w, "environment", before.Environment, after.Environment)
	writeCapBool(w, "shell", before.Shell, after.Shell)
	writeCapBool(w, "native_code", before.NativeCode, after.NativeCode)
	writeCapBool(w, "install_scripts", before.InstallScripts, after.InstallScripts)
	if before.State != after.State {
		fmt.Fprintf(w, "    state          %s → %s\n", before.State, after.State)
	}
}

func writeCapBool(w io.Writer, name string, before, after *bool) {
	b, bOK := boolLabel(before)
	a, aOK := boolLabel(after)
	if b == a && bOK == aOK {
		return
	}
	beforeOn := bOK && before != nil && *before
	afterOn := aOK && after != nil && *after
	switch {
	case !beforeOn && afterOn:
		fmt.Fprintf(w, "    + %s\n", name)
	case beforeOn && !afterOn:
		fmt.Fprintf(w, "    - %s\n", name)
	default:
		fmt.Fprintf(w, "    %-14s%s → %s\n", name, b, a)
	}
}

func writeCapFS(w io.Writer, before, after lockfile.FilesystemAccess) {
	if before == after {
		return
	}
	b := fsLabel(before)
	a := fsLabel(after)
	if before == "" && after != "" && after != lockfile.FilesystemNone {
		fmt.Fprintf(w, "    + filesystem (%s)\n", after)
		return
	}
	if after == "" && before != "" && before != lockfile.FilesystemNone {
		fmt.Fprintf(w, "    - filesystem (%s)\n", before)
		return
	}
	fmt.Fprintf(w, "    %-14s%s → %s\n", "filesystem", b, a)
}

func writeOwnership(w io.Writer, before, after Side) {
	if before.OwnershipState == after.OwnershipState &&
		before.Publisher == after.Publisher &&
		join(before.Maintainers) == join(after.Maintainers) {
		return
	}
	if before.Publisher != after.Publisher {
		bp := before.Publisher
		ap := after.Publisher
		if bp == "" {
			bp = "(none)"
		}
		if ap == "" {
			ap = "(none)"
		}
		fmt.Fprintf(w, "  publisher     %s → %s\n", bp, ap)
	}
	removed, added := listDelta(before.Maintainers, after.Maintainers)
	for _, name := range removed {
		fmt.Fprintf(w, "  maintainer removed: %s\n", name)
	}
	for _, name := range added {
		fmt.Fprintf(w, "  maintainer added: %s\n", name)
	}
	if before.OwnershipState != after.OwnershipState {
		fmt.Fprintf(w, "  ownership     %s → %s\n", before.OwnershipState, after.OwnershipState)
	}
}

func boolLabel(v *bool) (string, bool) {
	if v == nil {
		return "unknown", false
	}
	if *v {
		return "true", true
	}
	return "false", true
}

func fsLabel(v lockfile.FilesystemAccess) string {
	if v == "" {
		return "unknown"
	}
	return string(v)
}

func listDelta(before, after []string) (removed, added []string) {
	bset := make(map[string]struct{}, len(before))
	aset := make(map[string]struct{}, len(after))
	for _, v := range before {
		bset[v] = struct{}{}
	}
	for _, v := range after {
		aset[v] = struct{}{}
	}
	for _, v := range before {
		if _, ok := aset[v]; !ok {
			removed = append(removed, v)
		}
	}
	for _, v := range after {
		if _, ok := bset[v]; !ok {
			added = append(added, v)
		}
	}
	return removed, added
}

func displayName(artifactID string) string {
	_, name, ok := strings.Cut(artifactID, ":")
	if !ok || name == "" {
		return artifactID
	}
	if i := strings.Index(name, "#"); i >= 0 {
		return name[:i]
	}
	return name
}

// artifactKey identifies a subject (and optional filename) without version,
// so a version bump is a change to one subject rather than remove+add.
type artifactKey struct {
	Ecosystem string
	Name      string
	Filename  string
}

func keyOf(art lockfile.Artifact) artifactKey {
	return artifactKey{
		Ecosystem: art.Subject.Ecosystem,
		Name:      art.Subject.Name,
		Filename:  art.Filename,
	}
}

func (k artifactKey) id() string {
	id := k.subject()
	if k.Filename != "" {
		id += "#" + k.Filename
	}
	return id
}

func (k artifactKey) subject() string {
	return k.Ecosystem + ":" + k.Name
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
