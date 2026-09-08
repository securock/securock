package trust

import (
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

func Evaluate(art *lockfile.Artifact, pol policy.Document) {
	var reasons []string

	if pol.Rules.RequireNoVulnerabilities && len(art.Evidence.Vulnerabilities) > 0 {
		reasons = append(reasons, "known vulnerabilities")
	}
	if pol.Rules.RequireDigest && art.Digest == "" {
		reasons = append(reasons, "missing digest")
	}
	if pol.Rules.RequireProvenance && art.Evidence.Provenance != lockfile.EvidenceVerified {
		reasons = append(reasons, "provenance not verified")
	}
	if pol.Rules.RequireSignature && art.Evidence.Signature != lockfile.EvidenceVerified {
		reasons = append(reasons, "signature not verified")
	}

	if len(reasons) > 0 {
		art.Trust.Status = lockfile.StatusUntrusted
		art.Trust.Reasons = reasons
		return
	}

	art.Trust.Status = lockfile.StatusTrusted
	art.Trust.Reasons = nil
}

func MarkUnknown(art *lockfile.Artifact, reason string) {
	art.Trust.Status = lockfile.StatusUnknown
	if reason != "" {
		art.Trust.Reasons = []string{reason}
	}
}
