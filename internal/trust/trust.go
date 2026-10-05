package trust

import (
	"fmt"
	"slices"

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
	if pol.Rules.RequireDigest && art.Digest == "" {
		untrusted = append(untrusted, "missing digest")
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
