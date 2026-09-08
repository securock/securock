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
	if pol.Rules.RequireProvenance && !art.Evidence.Provenance.Present() {
		untrusted = append(untrusted, "provenance not present")
	}
	if pol.Rules.RequireSignature && !art.Evidence.Signature.Present() {
		untrusted = append(untrusted, "signature not present")
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
