package diff_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/securock/securock/internal/diff"
	"github.com/securock/securock/pkg/lockfile"
)

func TestCompareTrustDrift(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.1.0",
			Digest:  "sha256:aaa",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidenceVerified,
				Signature:  lockfile.EvidenceVerified,
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
		},
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"},
			Version: "2.3.1",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidenceVerified,
				Signature:  lockfile.EvidenceVerified,
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:bbb",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidenceVerified,
				Signature:  lockfile.EvidenceVerified,
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
		},
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"},
			Version: "2.4.0",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidenceMissing,
				Signature:  lockfile.EvidenceVerified,
			},
			Trust: lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"provenance not verified"}},
		},
	}}

	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("expected trust drift")
	}
	if got.TrustChanges() != 2 {
		t.Fatalf("trust changes = %d", got.TrustChanges())
	}

	var buf bytes.Buffer
	diff.Write(&buf, got)
	out := buf.String()
	if !strings.Contains(out, "react") || !strings.Contains(out, "19.1.0 → 19.2.0") {
		t.Fatalf("missing react version drift:\n%s", out)
	}
	if !strings.Contains(out, "Trust drift detected.") {
		t.Fatalf("missing drift footer:\n%s", out)
	}
}
