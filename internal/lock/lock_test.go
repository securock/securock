package lock_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/pkg/lockfile"
)

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	doc := lockfile.Document{
		Version:     1,
		GeneratedAt: time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC),
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
