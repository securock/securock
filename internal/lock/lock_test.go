package lock_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/pkg/lockfile"
)

func validEvidence() lockfile.Evidence {
	return lockfile.Evidence{
		Provenance: lockfile.EvidenceUnknown,
		Signature:  lockfile.EvidenceUnknown,
		Vulnerabilities: lockfile.VulnEvidence{
			State: lockfile.VulnUnknown,
		},
		Malicious:    lockfile.MaliciousEvidence{State: lockfile.VulnUnknown},
		Capabilities: lockfile.CapabilityEvidence{State: lockfile.CapUnknown},
		Behavior:     lockfile.BehaviorEvidence{State: lockfile.CapUnknown},
		Ownership:    lockfile.OwnershipEvidence{State: lockfile.CapUnknown},
		Chain:        lockfile.ChainEvidence{State: lockfile.EvidenceUnknown},
	}
}

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	doc := lockfile.Document{
		Version: lockfile.SchemaVersion,
		Artifacts: []lockfile.Artifact{
			{
				Subject:  lockfile.Subject{Ecosystem: "npm", Name: "react"},
				Version:  "19.2.0",
				Digest:   "sha256:abc",
				Evidence: validEvidence(),
				Trust:    lockfile.Trust{Status: lockfile.StatusTrusted},
			},
		},
	}
	if err := lock.Write(path, doc); err != nil {
		t.Fatal(err)
	}
	got, err := lock.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].Subject.Name != "react" {
		t.Fatalf("unexpected document: %#v", got)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	doc := lockfile.Document{
		Version: lockfile.SchemaVersion,
		Source:  lockfile.Source{Ecosystems: []string{"npm", "go"}},
		Artifacts: []lockfile.Artifact{
			{
				Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
				Version: "19.2.0",
				Evidence: lockfile.Evidence{
					Provenance: lockfile.EvidenceUnknown,
					Signature:  lockfile.EvidenceUnknown,
					Malicious:  lockfile.MaliciousEvidence{State: lockfile.VulnUnknown},
					Vulnerabilities: lockfile.VulnEvidence{
						State: lockfile.VulnChecked,
						Items: []lockfile.Vulnerability{
							{ID: "GHSA-b"},
							{ID: "GHSA-a"},
						},
					},
					Capabilities: lockfile.CapabilityEvidence{State: lockfile.CapUnknown},
					Behavior:     lockfile.BehaviorEvidence{State: lockfile.CapUnknown},
					Ownership:    lockfile.OwnershipEvidence{State: lockfile.CapUnknown},
					Chain:        lockfile.ChainEvidence{State: lockfile.EvidenceUnknown},
				},
				Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
			},
			{
				Subject:  lockfile.Subject{Ecosystem: "go", Name: "github.com/spf13/cobra"},
				Version:  "v1.9.1",
				Evidence: validEvidence(),
				Trust:    lockfile.Trust{Status: lockfile.StatusTrusted},
			},
		},
	}

	a, err := lock.Encode("securock.lock", doc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := lock.Encode("securock.lock", doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("lockfile encoding is not deterministic\n%s\n---\n%s", a, b)
	}
	if bytes.Contains(a, []byte("generated_at")) {
		t.Fatal("generated_at must not be encoded")
	}
	if bytes.Contains(a, []byte("path:")) {
		t.Fatal("source.path must not be encoded")
	}
}

func TestReadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	if err := os.WriteFile(path, []byte("version: 2\nbanana: true\nartifacts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Read(path); err == nil {
		t.Fatal("expected unknown field to fail")
	}
}

func TestReadRejectsOutdatedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	if err := os.WriteFile(path, []byte("version: 1\nartifacts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := lock.Read(path)
	if err == nil {
		t.Fatal("expected outdated version to fail")
	}
	if !strings.Contains(err.Error(), "outdated") || !strings.Contains(err.Error(), "securock lock") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadRejectsUnknownEcosystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	raw := []byte("version: 2\nartifacts:\n  - subject:\n      ecosystem: banana\n      name: x\n    version: \"1\"\n    evidence:\n      provenance: unknown\n      signature: unknown\n      vulnerabilities:\n        state: unknown\n      malicious:\n        state: unknown\n      capabilities:\n        state: unknown\n      behavior:\n        state: unknown\n      ownership:\n        state: unknown\n      chain:\n        state: unknown\n    trust:\n      status: trusted\n")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Read(path); err == nil {
		t.Fatal("expected unknown ecosystem to fail")
	}
}

func TestEncodeOmitsEmptyURLVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	doc := lockfile.Document{
		Version: lockfile.SchemaVersion,
		Artifacts: []lockfile.Artifact{
			{
				Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
				Source: lockfile.ArtifactSource{
					Resolver:  "deno",
					Requested: "https://esm.sh/preact",
					Resolved:  "https://esm.sh/preact@10.26.8",
				},
				Evidence: validEvidence(),
				Trust:    lockfile.Trust{Status: lockfile.StatusUnknown},
			},
		},
	}
	if err := lock.Write(path, doc); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("version: \"\"")) || bytes.Contains(raw, []byte("version: ''")) {
		t.Fatalf("empty version must be omitted:\n%s", raw)
	}
	got, err := lock.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Artifacts[0].Version != "" {
		t.Fatalf("version = %q", got.Artifacts[0].Version)
	}
	if got.Artifacts[0].Source.Resolved != "https://esm.sh/preact@10.26.8" {
		t.Fatalf("resolved = %q", got.Artifacts[0].Source.Resolved)
	}
}
