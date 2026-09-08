package lock_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/pkg/lockfile"
)

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	doc := lockfile.Document{
		Version: 1,
		Artifacts: []lockfile.Artifact{
			{
				Ecosystem: "npm",
				Name:      "react",
				Version:   "19.2.0",
				Digest:    "sha256:abc",
				Evidence: lockfile.Evidence{
					Provenance: lockfile.EvidenceUnknown,
					Signature:  lockfile.EvidenceUnknown,
				},
				Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
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
	if len(got.Artifacts) != 1 || got.Artifacts[0].Name != "react" {
		t.Fatalf("unexpected document: %#v", got)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	doc := lockfile.Document{
		Version: 1,
		Source:  lockfile.Source{Ecosystems: []string{"npm", "go"}},
		Artifacts: []lockfile.Artifact{
			{
				Ecosystem: "npm",
				Name:      "react",
				Version:   "19.2.0",
				Evidence: lockfile.Evidence{
					Provenance: lockfile.EvidenceUnknown,
					Signature:  lockfile.EvidenceUnknown,
					Vulnerabilities: []lockfile.Vulnerability{
						{ID: "GHSA-b"},
						{ID: "GHSA-a"},
					},
				},
				Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
			},
			{
				Ecosystem: "go",
				Name:      "github.com/spf13/cobra",
				Version:   "v1.9.1",
				Evidence: lockfile.Evidence{
					Provenance: lockfile.EvidenceUnknown,
					Signature:  lockfile.EvidenceUnknown,
				},
				Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
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
