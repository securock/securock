package explain_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/securock/securock/internal/explain"
	"github.com/securock/securock/pkg/lockfile"
)

func TestExplainTrustedPackage(t *testing.T) {
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:abc",
			Source:  lockfile.ArtifactSource{Registry: "https://registry.npmjs.org"},
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidencePresent,
				Signature:  lockfile.EvidencePresent,
				Vulnerabilities: lockfile.VulnEvidence{
					State: lockfile.VulnChecked,
				},
				Capabilities: lockfile.CapabilityEvidence{
					State:   lockfile.CapChecked,
					Network: lockfile.Bool(false),
				},
				Ownership: lockfile.OwnershipEvidence{
					State:     lockfile.CapChecked,
					Publisher: "alice",
				},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
		},
	}}
	got, err := explain.Find(doc, "react")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	explain.Write(&buf, got)
	out := buf.String()
	for _, want := range []string{
		"Why is react trusted?",
		"✓ digest matches",
		"✓ registry proven",
		"✓ provenance present",
		"✓ publisher recorded",
		"✓ capabilities locked",
		"✓ no known vulnerabilities",
		"verdict  trusted",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestExplainNotFound(t *testing.T) {
	_, err := explain.Find(lockfile.Document{}, "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}
