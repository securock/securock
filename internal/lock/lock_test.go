package lock_test

import (
	"bytes"
	"os"
	"path/filepath"
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
	}
}

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	doc := lockfile.Document{
		Version: 1,
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
		Version: 1,
		Source:  lockfile.Source{Ecosystems: []string{"npm", "go"}},
		Artifacts: []lockfile.Artifact{
			{
				Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
				Version: "19.2.0",
				Evidence: lockfile.Evidence{
					Provenance: lockfile.EvidenceUnknown,
					Signature:  lockfile.EvidenceUnknown,
					Vulnerabilities: lockfile.VulnEvidence{
						State: lockfile.VulnChecked,
						Items: []lockfile.Vulnerability{
							{ID: "GHSA-b"},
							{ID: "GHSA-a"},
						},
					},
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
	if err := os.WriteFile(path, []byte("version: 1\nbanana: true\nartifacts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Read(path); err == nil {
		t.Fatal("expected unknown field to fail")
	}
}

func TestReadRejectsUnknownEcosystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	raw := []byte("version: 1\nartifacts:\n  - subject:\n      ecosystem: banana\n      name: x\n    version: \"1\"\n    evidence:\n      provenance: unknown\n      signature: unknown\n      vulnerabilities:\n        state: unknown\n    trust:\n      status: trusted\n")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Read(path); err == nil {
		t.Fatal("expected unknown ecosystem to fail")
	}
}
