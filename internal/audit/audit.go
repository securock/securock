package audit

import (
	"fmt"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

// Run turns the evidence recorded for each artifact into severity-ranked findings.
// Unchecked evidence is reported as info: absence of a check is not a defect.
func Run(doc lockfile.Document) finding.Report {
	var out []finding.Finding
	for _, art := range doc.Artifacts {
		out = append(out, artifact(art)...)
	}
	return finding.New("audit", out)
}

func artifact(art lockfile.Artifact) []finding.Finding {
	subject := art.ArtifactID()
	ev := art.Evidence
	var out []finding.Finding
	add := func(id string, sev finding.Severity, title, detail, fix string) {
		out = append(out, finding.Finding{ID: id, Severity: sev, Title: title, Detail: detail, Subject: subject, Remediation: fix})
	}

	switch ev.Malicious.State {
	case lockfile.VulnChecked:
		for _, r := range ev.Malicious.Reports {
			add("malicious-package:"+r.ID, finding.SeverityCritical, "Package is reported as malicious", r.ID, "Remove the dependency and rotate any secrets it could read.")
		}
	default:
		add("malicious-unchecked", finding.SeverityInfo, "Malicious package reports were not checked", "", "Run without --offline to query OSV.")
	}

	switch ev.Vulnerabilities.State {
	case lockfile.VulnChecked:
		for _, v := range ev.Vulnerabilities.Items {
			add("known-vulnerability:"+v.ID, finding.SeverityHigh, "Known vulnerability", v.ID, "Upgrade to a fixed version.")
		}
	default:
		add("vulnerability-unchecked", finding.SeverityInfo, "Vulnerabilities were not checked", "", "Run without --offline to query OSV.")
	}

	if art.Digest == "" {
		add("missing-digest", finding.SeverityMedium, "Artifact has no digest", "", "Pin the artifact digest in the lockfile.")
	}
	if ev.Provenance == lockfile.EvidenceMissing {
		add("missing-provenance", finding.SeverityLow, "No provenance attestation", "", "Prefer releases published with provenance.")
	}
	if ev.Signature == lockfile.EvidenceMissing {
		add("missing-signature", finding.SeverityLow, "No signature", "", "Prefer signed releases.")
	}

	if ev.Capabilities.State == lockfile.CapChecked {
		caps := ev.Capabilities
		if enabled(caps.InstallScripts) {
			add("capability:install-scripts", finding.SeverityMedium, "Runs install scripts", "", "Review the scripts or disable them at install time.")
		}
		if enabled(caps.Shell) {
			add("capability:shell", finding.SeverityMedium, "Executes shell commands", "", "")
		}
		if enabled(caps.Network) {
			add("capability:network", finding.SeverityLow, "Uses the network", "", "")
		}
		if enabled(caps.NativeCode) {
			add("capability:native-code", finding.SeverityLow, "Contains native code", "", "")
		}
		if caps.Filesystem == lockfile.FilesystemWrite {
			add("capability:filesystem-write", finding.SeverityLow, "Writes to the filesystem", fmt.Sprint(caps.Filesystem), "")
		}
	}
	return out
}

func enabled(b *bool) bool {
	return b != nil && *b
}
