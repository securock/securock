package cli_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/schemas"
)

func TestOfflinePackageAttestationsAndSignerDrift(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	digest := strings.Repeat("a", 64)
	os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("version = 3\n[[package]]\nname = \"fixture\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \""+digest+"\"\n"), 0600)
	manifest := filepath.Join(dir, "attestations.json")
	keyFile := filepath.Join(dir, "signer.pub")
	writeEvidence := func(seed byte) {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		payload, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": "cargo:fixture@1.0.0", "digest": map[string]string{"sha256": digest}}}, "predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]any{"buildDefinition": map[string]any{"buildType": "https://builder.example/build/v1", "externalParameters": map[string]any{}}, "runDetails": map[string]any{"builder": map[string]string{"id": "https://builder.example/reviewed"}}}})
		pt := "application/vnd.in-toto+json"
		pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(pt), pt, len(payload), payload))
		raw, _ := json.Marshal(map[string]any{"version": 1, "attestations": []any{map[string]any{"payloadType": pt, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]string{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, pae))}}}}})
		os.WriteFile(manifest, raw, 0600)
		os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))), 0600)
	}
	args := []string{"scan", dir, "--offline", "--no-fail", "--format", "json", "--package-attestations", manifest, "--package-signer-key", keyFile}
	writeEvidence(1)
	first := runCLI(t, args...)
	if e := schemas.Validate("scan-report.schema.json", first); e != nil {
		t.Fatal(e)
	}
	var a, b lockfile.Document
	if e := json.Unmarshal(first, &a); e != nil {
		t.Fatal(e)
	}
	if len(a.Artifacts) != 1 || a.Artifacts[0].Evidence.Signature != lockfile.EvidenceVerified || a.Artifacts[0].Evidence.Provenance != lockfile.EvidenceVerified {
		t.Fatalf("%s", first)
	}
	runCLI(t, "lock", dir, "--offline", "--no-fail", "--package-attestations", manifest, "--package-signer-key", keyFile)
	runCLI(t, "verify", dir, "--offline", "--package-attestations", manifest, "--package-signer-key", keyFile)
	writeEvidence(2)
	second := runCLI(t, args...)
	json.Unmarshal(second, &b)
	if a.Policy.Digest == b.Policy.Digest {
		t.Fatal("signer pin change did not affect policy fingerprint")
	}
	if strings.Contains(string(first), keyFile) || strings.Contains(string(first), manifest) {
		t.Fatal("host-specific evidence paths leaked into lock output")
	}
}
