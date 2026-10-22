package sbom_test

import (
	"testing"

	"github.com/securock/securock/internal/sbom"
	"github.com/securock/securock/pkg/lockfile"
)

// The exports are checked against the official schemas, since SBOM consumers will.
func TestExportsAreValidAgainstTheOfficialSchemas(t *testing.T) {
	c := officialSchemas(t)

	rich := fixture(t)
	rich.Artifacts[0].Evidence.Health = &lockfile.HealthEvidence{License: "MIT OR Apache-2.0", Released: "2025-01-31"}
	rich.Artifacts[1].Evidence.Health = &lockfile.HealthEvidence{License: "Custom Terms 1.0"}
	rich.Artifacts[1].Evidence.Vulnerabilities.Items = []lockfile.Vulnerability{
		{ID: "GHSA-aaaa", Severity: lockfile.SeverityCritical, Fixed: []string{"4.17.21"}},
		{ID: "GHSA-bare"},
	}
	rich.Artifacts[1].Evidence.Malicious = lockfile.MaliciousEvidence{
		State: lockfile.VulnChecked, Reports: []lockfile.MaliciousReport{{ID: "MAL-2024-1"}},
	}

	for name, doc := range map[string]lockfile.Document{
		"rich":  rich,
		"empty": {Version: lockfile.SchemaVersion},
		"urls":  {Version: lockfile.SchemaVersion, Artifacts: []lockfile.Artifact{art("url", "https://esm.sh/preact", "", "")}},
	} {
		t.Run(name, func(t *testing.T) {
			validateAgainst(t, c, "http://cyclonedx.org/schema/bom-1.6.schema.json", cdx(t, doc, sbom.Options{ToolVersion: "1.2.3"}))
			validateAgainst(t, c, "http://spdx.org/rdf/terms/2.3", spdx(t, doc, sbom.Options{ToolVersion: "1.2.3"}))
		})
	}
}
