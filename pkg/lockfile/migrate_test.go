package lockfile_test

import (
	"testing"

	"github.com/securock/securock/pkg/lockfile"
)

func TestMigrateV1(t *testing.T) {
	v1 := lockfile.V1Document{
		Version: 1,
		Source:  lockfile.Source{Ecosystems: []string{"npm"}, Resolvers: []string{"npm"}},
		Policy:  lockfile.PolicyRef{Digest: "sha256:policy"},
		Artifacts: []lockfile.V1Artifact{{
			Subject:  lockfile.Subject{Ecosystem: "npm", Name: "ms"},
			Version:  "2.1.3",
			Digest:   "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			Filename: "ms.tgz",
			Source: lockfile.ArtifactSource{
				Resolver: "npm",
				Kind:     "registry",
				Registry: "https://registry.npmjs.org",
			},
			Evidence: lockfile.V1Evidence{
				Provenance: lockfile.EvidencePresent,
				Signature:  lockfile.EvidenceVerified,
				Vulnerabilities: lockfile.VulnEvidence{
					State: lockfile.VulnChecked,
					Items: []lockfile.Vulnerability{{ID: "GHSA-1"}},
				},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted, Reasons: []string{"ok"}},
		}},
	}

	got, err := lockfile.MigrateV1(v1)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != lockfile.SchemaVersion {
		t.Fatalf("version = %d", got.Version)
	}
	if got.Policy.Digest != "sha256:policy" {
		t.Fatalf("policy = %#v", got.Policy)
	}
	art := got.Artifacts[0]
	if art.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" || art.Filename != "ms.tgz" || art.Source.Registry == "" {
		t.Fatalf("kept fields: %#v", art)
	}
	if art.Evidence.Provenance != lockfile.EvidencePresent || art.Evidence.Signature != lockfile.EvidenceVerified {
		t.Fatalf("kept evidence: %#v", art.Evidence)
	}
	if art.Evidence.Vulnerabilities.State != lockfile.VulnChecked || art.Evidence.Vulnerabilities.Items[0].ID != "GHSA-1" {
		t.Fatalf("kept vulns: %#v", art.Evidence.Vulnerabilities)
	}
	if art.Evidence.Malicious.State != lockfile.VulnUnknown ||
		art.Evidence.Capabilities.State != lockfile.CapUnknown ||
		art.Evidence.Behavior.State != lockfile.CapUnknown ||
		art.Evidence.Ownership.State != lockfile.CapUnknown ||
		art.Evidence.Chain.State != lockfile.EvidenceUnknown {
		t.Fatalf("new axes must be unknown: %#v", art.Evidence)
	}
	if art.Trust.Status != lockfile.StatusUnknown || len(art.Trust.Reasons) != 0 {
		t.Fatalf("trust must reset: %#v", art.Trust)
	}
}

func TestMigrateV1RejectsWrongVersion(t *testing.T) {
	_, err := lockfile.MigrateV1(lockfile.V1Document{Version: 2})
	if err == nil {
		t.Fatal("expected version mismatch error")
	}
}
