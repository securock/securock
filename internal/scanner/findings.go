package scanner

import (
	"strings"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

// Findings reports every artifact that did not pass the active policy.
// Untrusted artifacts failed a rule; unknown artifacts lack evidence to decide.
func Findings(tool string, doc lockfile.Document) finding.Report {
	var out []finding.Finding
	for _, art := range doc.Artifacts {
		f := finding.Finding{
			Detail:  strings.Join(art.Trust.Reasons, ", "),
			Subject: art.ArtifactID(),
		}
		switch art.Trust.Status {
		case lockfile.StatusTrusted:
			continue
		case lockfile.StatusUntrusted:
			f.ID, f.Severity, f.Title = "untrusted-artifact", finding.SeverityHigh, "Artifact failed the active policy"
			f.Remediation = "Run securock explain for the failing checks."
		default:
			f.ID, f.Severity, f.Title = "unknown-artifact", finding.SeverityMedium, "Artifact trust could not be determined"
			f.Remediation = "Run without --offline so remote evidence can be collected."
		}
		out = append(out, f)
	}
	return finding.New(tool, out)
}
