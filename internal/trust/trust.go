package trust

import (
	"fmt"
	"slices"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func Evaluate(art *lockfile.Artifact, pol policy.Document) {
	var untrusted []string
	var unknown []string

	if pol.Rules.DenyVulnerabilities() {
		switch art.Evidence.Vulnerabilities.State {
		case lockfile.VulnChecked:
			if len(art.Evidence.Vulnerabilities.Items) > 0 {
				untrusted = append(untrusted, "known vulnerabilities")
			}
		default:
			unknown = append(unknown, "vulnerabilities not checked")
		}
	}
	if pol.Rules.DenyMalicious() {
		switch art.Evidence.Malicious.State {
		case lockfile.VulnChecked:
			if len(art.Evidence.Malicious.Reports) > 0 {
				untrusted = append(untrusted, "malicious package")
			}
		default:
			unknown = append(unknown, "malicious reports not checked")
		}
	}
	if pol.Rules.RequireDigest {
		switch {
		case art.Digest == "":
			untrusted = append(untrusted, "missing digest")
		case core.StrongDigest(art.Digest) != nil:
			untrusted = append(untrusted, "invalid digest")
		}
	}
	if need := evidenceFloor(pol.Rules.Provenance.Minimum, pol.Rules.RequireProvenance); need != "" {
		if !meets(art.Evidence.Provenance, need) {
			if need == lockfile.EvidenceVerified {
				untrusted = append(untrusted, "provenance not verified")
			} else {
				untrusted = append(untrusted, "provenance not present")
			}
		}
	}
	if pol.Rules.Provenance.OriginConfigured() {
		switch art.Evidence.Chain.State {
		case lockfile.EvidenceUnknown:
			unknown = append(unknown, "provenance origin not checked")
		case lockfile.EvidenceVerified:
			untrusted = append(untrusted, provenanceOriginViolations(art.Evidence.Chain, pol.Rules.Provenance)...)
		default:
			untrusted = append(untrusted, "provenance origin not verified")
		}
	}
	if need := evidenceFloor(pol.Rules.Signature.Minimum, pol.Rules.RequireSignature); need != "" {
		if !meets(art.Evidence.Signature, need) {
			if need == lockfile.EvidenceVerified {
				untrusted = append(untrusted, "signature not verified")
			} else {
				untrusted = append(untrusted, "signature not present")
			}
		}
	}
	if pol.Rules.Capabilities.Configured() {
		switch art.Evidence.Capabilities.State {
		case lockfile.CapChecked:
			untrusted = append(untrusted, capabilityViolations(art.Evidence.Capabilities, pol.Rules.Capabilities)...)
		default:
			unknown = append(unknown, "capabilities not checked")
		}
	}

	switch {
	case len(untrusted) > 0:
		art.Trust.Status = lockfile.StatusUntrusted
		art.Trust.Reasons = untrusted
	case len(unknown) > 0:
		art.Trust.Status = lockfile.StatusUnknown
		art.Trust.Reasons = unknown
	default:
		art.Trust.Status = lockfile.StatusTrusted
		art.Trust.Reasons = nil
	}
}

func MarkUnknown(art *lockfile.Artifact, reason string) {
	art.Trust.Status = lockfile.StatusUnknown
	if reason != "" {
		art.Trust.Reasons = []string{reason}
	}
}

func capabilityViolations(caps lockfile.CapabilityEvidence, rule policy.CapabilityRule) []string {
	var out []string
	for _, name := range rule.Deny {
		if capabilityEnabled(caps, name) {
			out = append(out, fmt.Sprintf("denied capability: %s", name))
		}
	}
	if rule.Filesystem.Maximum != "" {
		got := caps.Filesystem
		if got == "" {
			got = lockfile.FilesystemNone
		}
		if filesystemRank(got) > filesystemRank(lockfile.FilesystemAccess(rule.Filesystem.Maximum)) {
			out = append(out, fmt.Sprintf("filesystem exceeds maximum: %s > %s", got, rule.Filesystem.Maximum))
		}
	}
	slices.Sort(out)
	return out
}

func provenanceOriginViolations(chain lockfile.ChainEvidence, rule policy.EvidenceRule) []string {
	var out []string
	if len(rule.AllowSources) > 0 && !matchSource(chain.Source, rule.AllowSources) {
		out = append(out, "provenance source not allowed")
	}
	if len(rule.AllowBuilders) > 0 && !matchBuilder(chain.Builder, rule.AllowBuilders) {
		out = append(out, "provenance builder not allowed")
	}
	if len(rule.AllowWorkflows) > 0 && !matchWorkflow(chain.Workflow, rule.AllowWorkflows) {
		out = append(out, "provenance workflow not allowed")
	}
	if len(rule.AllowRefs) > 0 && !matchExact(chain.Ref, rule.AllowRefs) {
		out = append(out, "provenance ref not allowed")
	}
	if len(rule.AllowPredicateTypes) > 0 && !matchExact(chain.PredicateType, rule.AllowPredicateTypes) {
		out = append(out, "provenance predicate type not allowed")
	}
	slices.Sort(out)
	return out
}

func matchSource(got string, allow []string) bool {
	got = normalizeSource(got)
	if got == "" {
		return false
	}
	for _, entry := range allow {
		if got == normalizeSource(entry) {
			return true
		}
	}
	return false
}

func matchBuilder(got string, allow []string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	for _, entry := range allow {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if got == entry || strings.HasPrefix(got, entry+"@") || strings.HasPrefix(got, entry+"/") {
			return true
		}
	}
	return false
}

func matchWorkflow(got string, allow []string) bool {
	got = workflowBase(got)
	if got == "" {
		return false
	}
	for _, entry := range allow {
		if got == workflowBase(entry) {
			return true
		}
	}
	return false
}

func matchExact(got string, allow []string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	for _, entry := range allow {
		if got == strings.TrimSpace(entry) {
			return true
		}
	}
	return false
}

func workflowBase(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func normalizeSource(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "git+")
	if !strings.HasPrefix(s, "git@") {
		if i := strings.LastIndex(s, "@"); i > 0 {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "ssh://git@")
	s = strings.TrimPrefix(s, "git@")
	s = strings.Replace(s, ":", "/", 1)
	return strings.TrimSuffix(s, "/")
}

func capabilityEnabled(caps lockfile.CapabilityEvidence, name string) bool {
	switch name {
	case "network":
		return caps.Network != nil && *caps.Network
	case "environment":
		return caps.Environment != nil && *caps.Environment
	case "shell":
		return caps.Shell != nil && *caps.Shell
	case "native_code":
		return caps.NativeCode != nil && *caps.NativeCode
	case "install_scripts":
		return caps.InstallScripts != nil && *caps.InstallScripts
	case "filesystem":
		return caps.Filesystem == lockfile.FilesystemRead || caps.Filesystem == lockfile.FilesystemWrite
	default:
		return false
	}
}

func filesystemRank(v lockfile.FilesystemAccess) int {
	switch v {
	case lockfile.FilesystemWrite:
		return 3
	case lockfile.FilesystemRead:
		return 2
	case lockfile.FilesystemNone, "":
		return 1
	default:
		return 0
	}
}

func evidenceFloor(minimum string, legacy bool) lockfile.EvidenceState {
	switch minimum {
	case "verified":
		return lockfile.EvidenceVerified
	case "present":
		return lockfile.EvidencePresent
	}
	if legacy {
		return lockfile.EvidencePresent
	}
	return ""
}

func meets(got, need lockfile.EvidenceState) bool {
	order := map[lockfile.EvidenceState]int{
		lockfile.EvidenceUnknown:  0,
		lockfile.EvidenceMissing:  1,
		lockfile.EvidencePresent:  2,
		lockfile.EvidenceVerified: 3,
	}
	return order[got] >= order[need]
}
