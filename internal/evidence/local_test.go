package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/pkg/lockfile"
)

func signedPackageManifest(t *testing.T, identity, digest string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	algorithm, value, _ := strings.Cut(digest, ":")
	payload, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": identity, "digest": map[string]string{algorithm: value}}}, "predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]any{"buildDefinition": map[string]any{"buildType": "https://builder.example/build/v1", "externalParameters": map[string]any{}}, "runDetails": map[string]any{"builder": map[string]string{"id": "https://builder.example/reviewed"}}}})
	pt := "application/vnd.in-toto+json"
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(pt), pt, len(payload), payload))
	raw, _ := json.Marshal(map[string]any{"version": 1, "attestations": []any{map[string]any{"payloadType": pt, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]string{"keyid": "reviewed", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, pae))}}}}})
	return raw, key.Public().(ed25519.PublicKey)
}

func TestPinnedPackageStatementsAcrossEcosystems(t *testing.T) {
	for _, ecosystemName := range []string{"go", "cargo", "nuget"} {
		t.Run(ecosystemName, func(t *testing.T) {
			digest := "sha256:" + strings.Repeat("a", 64)
			if ecosystemName == "go" {
				digest = "goh1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			}
			dep := ecosystem.Dependency{Ecosystem: ecosystemName, Name: "example", Version: "1.0.0", Digest: digest}
			raw, key := signedPackageManifest(t, evidence.Key(dep), digest)
			statements, e := evidence.ReadPinned(bytes.NewReader(raw), key)
			if e != nil {
				t.Fatal(e)
			}
			matched, e := evidence.MatchPinned(statements, []ecosystem.Dependency{dep})
			if e != nil {
				t.Fatal(e)
			}
			record := matched[evidence.Key(dep)]
			if record.Provenance != lockfile.EvidenceVerified || record.Signature != lockfile.EvidenceVerified || record.Chain.Builder != "https://builder.example/reviewed" {
				t.Fatal(record)
			}
			dep.Digest = "sha256:" + strings.Repeat("b", 64)
			if _, e = evidence.MatchPinned(statements, []ecosystem.Dependency{dep}); e == nil {
				t.Fatal("signed digest mismatch accepted")
			}
			if _, e = evidence.ReadPinned(bytes.NewReader(raw), bytes.Repeat([]byte{1}, 32)); e == nil {
				t.Fatal("untrusted signer accepted")
			}
			dep.Name = "other"
			matched, e = evidence.MatchPinned(statements, []ecosystem.Dependency{dep})
			if e != nil || len(matched) != 0 {
				t.Fatal("different package accepted", e)
			}
		})
	}
}
