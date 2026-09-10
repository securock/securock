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

func TestCompareRedirectResolved(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
			Version: "aaa",
			Digest:  "sha256:aaa",
			Source: lockfile.ArtifactSource{
				Resolver:  "deno",
				Requested: "https://esm.sh/preact",
				Resolved:  "https://esm.sh/preact@10.26.8",
			},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
			Version: "aaa",
			Digest:  "sha256:aaa",
			Source: lockfile.ArtifactSource{
				Resolver:  "deno",
				Requested: "https://esm.sh/preact",
				Resolved:  "https://esm.sh/preact@10.26.9",
			},
		},
	}}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("deno redirect target change must be trust drift")
	}
}

func TestCompareURLRedirectSubject(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
			Source: lockfile.ArtifactSource{
				Resolver:  "deno",
				Requested: "https://esm.sh/preact",
				Resolved:  "https://esm.sh/preact@10.26.8",
			},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
			Source: lockfile.ArtifactSource{
				Resolver:  "deno",
				Requested: "https://esm.sh/preact",
				Resolved:  "https://esm.sh/preact@10.26.9",
			},
		},
	}}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("redirect target change must be trust drift")
	}
	if len(got.Changes) != 1 {
		t.Fatalf("changes = %#v", got.Changes)
	}
	if got.Changes[0].Subject != "url:https://esm.sh/preact" {
		t.Fatalf("subject = %s", got.Changes[0].Subject)
	}
	if got.Changes[0].Artifact != "url:https://esm.sh/preact" {
		t.Fatalf("artifact = %s", got.Changes[0].Artifact)
	}
}

func TestCompareRegistryDrift(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:aaa",
			Source: lockfile.ArtifactSource{
				Resolver: "npm",
				Kind:     "registry",
				Registry: "https://registry.example-a.com",
			},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:aaa",
			Source: lockfile.ArtifactSource{
				Resolver: "npm",
				Kind:     "registry",
				Registry: "https://registry.example-b.com",
			},
		},
	}}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("registry change must be trust drift")
	}
	if len(got.Changes) != 1 {
		t.Fatalf("changes = %#v", got.Changes)
	}
}

func TestCompareArtifactURLDrift(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "cargo", Name: "foo"},
			Version: "1.0.0",
			Source: lockfile.ArtifactSource{
				Resolver: "cargo",
				Kind:     "git",
				Artifact: "https://github.com/example/foo",
				Resolved: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "cargo", Name: "foo"},
			Version: "1.0.0",
			Source: lockfile.ArtifactSource{
				Resolver: "cargo",
				Kind:     "git",
				Artifact: "https://github.com/other/foo",
				Resolved: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("artifact url change must be trust drift")
	}
}

func TestCompareSourceKindDrift(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "pypi", Name: "foo"},
			Version: "1.0.0",
			Source:  lockfile.ArtifactSource{Resolver: "uv", Kind: "registry", Registry: "https://pypi.org"},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "pypi", Name: "foo"},
			Version: "1.0.0",
			Source:  lockfile.ArtifactSource{Resolver: "uv", Kind: "git", Artifact: "https://github.com/example/foo"},
		},
	}}
	got := diff.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("source kind change must be trust drift")
	}
}
