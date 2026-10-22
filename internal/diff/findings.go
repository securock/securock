package diff

import (
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Findings turns trust drift into findings so it can be written in any report format.
// Only trust-relevant changes are reported, matching Write and TrustDrift.
func (r Result) Findings(tool string) finding.Report {
	var out []finding.Finding
	if r.PolicyBefore != r.PolicyAfter {
		out = append(out, finding.Finding{
			ID:          "policy-changed",
			Severity:    finding.SeverityHigh,
			Title:       "Policy changed since the lockfile was written",
			Detail:      r.PolicyBefore + " -> " + r.PolicyAfter,
			Remediation: "Review the policy change, then run securock lock to accept it.",
		})
	}
	for _, id := range r.Removed {
		out = append(out, finding.Finding{
			ID: "artifact-removed", Severity: finding.SeverityHigh, Title: "Artifact was removed", Subject: id,
			Remediation: "Run securock lock if the removal is intended.",
		})
	}
	for _, id := range r.Added {
		out = append(out, finding.Finding{
			ID: "artifact-added", Severity: finding.SeverityHigh, Title: "Artifact was added", Subject: id,
			Remediation: "Review the new dependency, then run securock lock to accept it.",
		})
	}
	for _, c := range r.Changes {
		if !trustRelevant(c.Before, c.After, r.Policy) {
			continue
		}
		out = append(out, finding.Finding{
			ID:          "trust-drift",
			Severity:    finding.SeverityHigh,
			Title:       "Trust evidence changed",
			Detail:      strings.Join(changedFields(c), ", "),
			Subject:     c.Artifact,
			Remediation: "Run securock diff for details, then run securock lock to accept the change.",
		})
	}
	return finding.New(tool, out)
}

// changedFields names the evidence fields that differ between the two sides.
func changedFields(c Change) []string {
	a, b := c.Before, c.After
	checks := []struct {
		name string
		diff bool
	}{
		{"version", join(a.Versions) != join(b.Versions)},
		{"digest", join(a.Digests) != join(b.Digests)},
		{"provenance", a.Provenance != b.Provenance},
		{"signature", a.Signature != b.Signature},
		{"vulnerabilities", a.VulnState != b.VulnState || join(a.Vulns) != join(b.Vulns)},
		{"malicious", a.MaliciousState != b.MaliciousState || join(a.Malicious) != join(b.Malicious)},
		{"trust", a.Trust != b.Trust || join(a.TrustReason) != join(b.TrustReason)},
		{"source", sourceChanged(a, b)},
		{"capabilities", !capabilitiesEqual(a.Capabilities, b.Capabilities)},
		{"behavior", !behaviorEqual(a.Behavior, b.Behavior)},
		{"chain", !chainEqual(a.Chain, b.Chain)},
		{"ownership", ownershipChanged(a, b)},
	}
	var out []string
	for _, c := range checks {
		if c.diff {
			out = append(out, c.name)
		}
	}
	return out
}
