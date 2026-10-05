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
	got, migrated, err := lock.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("v2 lockfile must not report migration")
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
	if _, _, err := lock.Read(path); err == nil {
		t.Fatal("expected unknown field to fail")
	}
}

func TestReadRejectsUnknownEcosystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	raw := []byte("version: 2\nartifacts:\n  - subject:\n      ecosystem: banana\n      name: x\n    version: \"1\"\n    evidence:\n      provenance: unknown\n      signature: unknown\n      vulnerabilities:\n        state: unknown\n      malicious:\n        state: unknown\n      capabilities:\n        state: unknown\n      behavior:\n        state: unknown\n      ownership:\n        state: unknown\n      chain:\n        state: unknown\n    trust:\n      status: trusted\n")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lock.Read(path); err == nil {
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
	got, migrated, err := lock.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("v2 lockfile must not report migration")
	}
	if got.Artifacts[0].Version != "" {
		t.Fatalf("version = %q", got.Artifacts[0].Version)
	}
	if got.Artifacts[0].Source.Resolved != "https://esm.sh/preact@10.26.8" {
		t.Fatalf("resolved = %q", got.Artifacts[0].Source.Resolved)
	}
}

func TestReadMigratesV1FixtureYAML(t *testing.T) {
	assertMigratesV1Fixture(t, "npm.securock.lock")
}

func TestReadMigratesV1FixtureJSON(t *testing.T) {
	assertMigratesV1Fixture(t, "npm.securock.lock.json")
}

func assertMigratesV1Fixture(t *testing.T, name string) {
	t.Helper()
	src := filepath.Join("testdata", "v1", name)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got, migrated, err := lock.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected v1 migration")
	}
	if got.Version != lockfile.SchemaVersion {
		t.Fatalf("version = %d", got.Version)
	}
	if len(got.Artifacts) != 1 {
		t.Fatalf("artifacts = %d", len(got.Artifacts))
	}
	art := got.Artifacts[0]
	if art.Subject.Name != "ms" || art.Version != "2.1.3" {
		t.Fatalf("artifact identity: %#v", art)
	}
	if art.Digest == "" || art.Source.Registry == "" {
		t.Fatalf("digest/source must be kept: %#v", art)
	}
	if art.Evidence.Provenance != lockfile.EvidenceUnknown || art.Evidence.Signature != lockfile.EvidenceUnknown {
		t.Fatalf("provenance/signature: %#v", art.Evidence)
	}
	if art.Evidence.Vulnerabilities.State != lockfile.VulnUnknown {
		t.Fatalf("vulnerabilities: %#v", art.Evidence.Vulnerabilities)
	}
	assertV2UnknownAxes(t, art)
	if art.Trust.Status != lockfile.StatusUnknown {
		t.Fatalf("trust = %q", art.Trust.Status)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only migration must not rewrite the lockfile")
	}
}

func TestReadResetsV1TrustedToUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	raw := []byte(`version: 1
artifacts:
  - subject:
      ecosystem: npm
      name: leftpad
    version: "1.0.0"
    digest: sha256:abc
    evidence:
      provenance: present
      signature: missing
      vulnerabilities:
        state: checked
        items:
          - id: GHSA-aaaa
    trust:
      status: trusted
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	got, migrated, err := lock.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected migration")
	}
	art := got.Artifacts[0]
	if art.Evidence.Provenance != lockfile.EvidencePresent {
		t.Fatalf("provenance kept = %q", art.Evidence.Provenance)
	}
	if art.Evidence.Signature != lockfile.EvidenceMissing {
		t.Fatalf("signature kept = %q", art.Evidence.Signature)
	}
	if art.Evidence.Vulnerabilities.State != lockfile.VulnChecked || len(art.Evidence.Vulnerabilities.Items) != 1 {
		t.Fatalf("vulnerabilities kept: %#v", art.Evidence.Vulnerabilities)
	}
	assertV2UnknownAxes(t, art)
	if art.Trust.Status != lockfile.StatusUnknown {
		t.Fatalf("trusted must become unknown, got %q", art.Trust.Status)
	}
	if len(art.Trust.Reasons) != 0 {
		t.Fatalf("trust reasons must be cleared, got %#v", art.Trust.Reasons)
	}
}

func TestReadRejectsV1UnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	raw := []byte(`version: 1
artifacts:
  - subject:
      ecosystem: npm
      name: x
    version: "1"
    evidence:
      provenance: unknown
      signature: unknown
      vulnerabilities:
        state: unknown
      malicious:
        state: unknown
    trust:
      status: unknown
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lock.Read(path); err == nil {
		t.Fatal("v1 decode must reject v2-only evidence fields")
	}
}

func TestReadRejectsBrokenV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	raw := []byte(`version: 1
artifacts:
  - subject:
      ecosystem: npm
      name: x
    version: "1"
    evidence:
      provenance: banana
      signature: unknown
      vulnerabilities:
        state: unknown
    trust:
      status: unknown
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lock.Read(path); err == nil {
		t.Fatal("expected invalid v1 evidence state to fail")
	}
}

func TestReadRejectsVersionZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	if err := os.WriteFile(path, []byte("version: 0\nartifacts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := lock.Read(path)
	if err == nil {
		t.Fatal("expected version 0 to fail")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadRejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "securock.lock")
	if err := os.WriteFile(path, []byte("version: 3\nartifacts: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := lock.Read(path)
	if err == nil {
		t.Fatal("expected future version to fail")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrationCanonicalEncodingStable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "v1", "npm.securock.lock"))
	if err != nil {
		t.Fatal(err)
	}
	doc, migrated, err := lock.Parse("securock.lock", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("expected migration")
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
		t.Fatal("migrated encoding must be deterministic")
	}

	// Re-reading the encoded v2 bytes must not migrate again and must round-trip.
	again, migratedAgain, err := lock.Parse("securock.lock", a)
	if err != nil {
		t.Fatal(err)
	}
	if migratedAgain {
		t.Fatal("v2 encoding must not migrate")
	}
	c, err := lock.Encode("securock.lock", again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) {
		t.Fatalf("second encode changed bytes\n%s\n---\n%s", a, c)
	}
}

func TestMigrateV1TwiceIsIdempotent(t *testing.T) {
	v1 := lockfile.V1Document{
		Version: 1,
		Artifacts: []lockfile.V1Artifact{{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "ms"},
			Version: "2.1.3",
			Digest:  "sha256:abc",
			Evidence: lockfile.V1Evidence{
				Provenance:      lockfile.EvidencePresent,
				Signature:       lockfile.EvidenceMissing,
				Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted, Reasons: []string{"ok"}},
		}},
	}
	first, err := lockfile.MigrateV1(v1)
	if err != nil {
		t.Fatal(err)
	}
	// Second pass: encoding as current schema then reading as v2 (no MigrateV1).
	encoded, err := lock.Encode("securock.lock", first)
	if err != nil {
		t.Fatal(err)
	}
	second, migrated, err := lock.Parse("securock.lock", encoded)
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("already-migrated document must not migrate again")
	}
	firstEnc, err := lock.Encode("securock.lock", first)
	if err != nil {
		t.Fatal(err)
	}
	secondEnc, err := lock.Encode("securock.lock", second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstEnc, secondEnc) {
		t.Fatalf("idempotent migration failed\n%s\n---\n%s", firstEnc, secondEnc)
	}
}

func assertV2UnknownAxes(t *testing.T, art lockfile.Artifact) {
	t.Helper()
	if art.Evidence.Malicious.State != lockfile.VulnUnknown {
		t.Fatalf("malicious = %q", art.Evidence.Malicious.State)
	}
	if art.Evidence.Capabilities.State != lockfile.CapUnknown {
		t.Fatalf("capabilities = %q", art.Evidence.Capabilities.State)
	}
	if art.Evidence.Behavior.State != lockfile.CapUnknown {
		t.Fatalf("behavior = %q", art.Evidence.Behavior.State)
	}
	if art.Evidence.Ownership.State != lockfile.CapUnknown {
		t.Fatalf("ownership = %q", art.Evidence.Ownership.State)
	}
	if art.Evidence.Chain.State != lockfile.EvidenceUnknown {
		t.Fatalf("chain = %q", art.Evidence.Chain.State)
	}
}
