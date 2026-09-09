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
	if got.TrustChanges() != 4 {
		t.Fatalf("trust changes = %d", got.TrustChanges())
	}

	var buf bytes.Buffer
	diff.Write(&buf, got)
	out := buf.String()
	if !strings.Contains(out, "react@19.1.0") || !strings.Contains(out, "react@19.2.0") {
		t.Fatalf("missing react artifact drift:\n%s", out)
	}
	if !strings.Contains(out, "Trust drift detected.") {
		t.Fatalf("missing drift footer:\n%s", out)
	}
}

func TestCompareVulnerabilityIDs(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"},
			Version: "1.0.0",
			Evidence: lockfile.Evidence{
				Vulnerabilities: lockfile.VulnEvidence{
					State: lockfile.VulnChecked,
					Items: []lockfile.Vulnerability{{ID: "CVE-A"}},
				},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerabilities"}},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"},
			Version: "1.0.0",
			Evidence: lockfile.Evidence{
				Vulnerabilities: lockfile.VulnEvidence{
					State: lockfile.VulnChecked,
					Items: []lockfile.Vulnerability{{ID: "CVE-B"}},
				},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerabilities"}},
		},
	}}

	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("vulnerability id swap must be trust drift")
	}
}

func TestComparePolicyDigest(t *testing.T) {
	locked := lockfile.Document{
		Policy: lockfile.PolicyRef{Digest: "sha256:aaa"},
		Artifacts: []lockfile.Artifact{
			{Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"}, Version: "1.0.0"},
		},
	}
	current := lockfile.Document{
		Policy: lockfile.PolicyRef{Digest: "sha256:bbb"},
		Artifacts: []lockfile.Artifact{
			{Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"}, Version: "1.0.0"},
		},
	}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("policy digest change must be trust drift")
	}
}

func TestWriteJSON(t *testing.T) {
	got := diff.Compare(
		lockfile.Document{Policy: lockfile.PolicyRef{Digest: "sha256:aaa"}},
		lockfile.Document{Policy: lockfile.PolicyRef{Digest: "sha256:bbb"}},
	)
	var buf bytes.Buffer
	if err := diff.WriteJSON(&buf, got); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"schema_version": 1`) {
		t.Fatalf("missing schema_version:\n%s", out)
	}
	if !strings.Contains(out, `"trust_drift": true`) {
		t.Fatalf("missing trust_drift:\n%s", out)
	}
}

func TestCompareTrustReason(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"},
			Version: "1.0.0",
			Trust:   lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"provenance not present"}},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "foo"},
			Version: "1.0.0",
			Trust:   lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerabilities"}},
		},
	}}

	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("trust reason change must be trust drift")
	}
}

func TestCompareArtifactDigestSwap(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "pypi", Name: "foo"}, Version: "1.0.0", Filename: "foo-linux.whl", Digest: "sha256:aaa"},
		{Subject: lockfile.Subject{Ecosystem: "pypi", Name: "foo"}, Version: "1.0.0", Filename: "foo-macos.whl", Digest: "sha256:bbb"},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "pypi", Name: "foo"}, Version: "1.0.0", Filename: "foo-linux.whl", Digest: "sha256:bbb"},
		{Subject: lockfile.Subject{Ecosystem: "pypi", Name: "foo"}, Version: "1.0.0", Filename: "foo-macos.whl", Digest: "sha256:aaa"},
	}}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("per-file digest swap must be trust drift")
	}
	if len(got.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(got.Changes))
	}
}
