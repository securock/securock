package scanner_test

import (
	"testing"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/scanner"
	"github.com/securock/securock/pkg/lockfile"
)

func TestFindingsSkipTrustedArtifacts(t *testing.T) {
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "ok"}, Version: "1", Trust: lockfile.Trust{Status: lockfile.StatusTrusted}},
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "bad"}, Version: "1", Trust: lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerability"}}},
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "unk"}, Version: "1", Trust: lockfile.Trust{Status: lockfile.StatusUnknown}},
	}}

	report := scanner.Findings("scan", doc)
	if len(report.Findings) != 2 {
		t.Fatalf("findings: %+v", report.Findings)
	}
	bad, unk := report.Findings[0], report.Findings[1]
	if bad.ID != "untrusted-artifact" || bad.Severity != finding.SeverityHigh || bad.Subject != "npm:bad@1" || bad.Detail != "known vulnerability" {
		t.Fatalf("untrusted finding: %+v", bad)
	}
	if unk.ID != "unknown-artifact" || unk.Severity != finding.SeverityMedium {
		t.Fatalf("unknown finding: %+v", unk)
	}
}
