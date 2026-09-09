package trust

import (
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func Evaluate(art *lockfile.Artifact, pol policy.Document) {
	var untrusted []string
	var unknown []string

	if pol.Rules.RequireNoVulnerabilities {
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
