package evidence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
)

func TestVerifySignatureECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := keyFingerprint(der)
	integrity := "sha512-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
	digest := core.NormalizeDigest(integrity)
	msg := []byte("pkg@1.0.0:" + integrity)
	sum := sha256.Sum256(msg)
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	keysJSON, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{
				"keyid":   keyID,
				"keytype": "ecdsa-sha2-nistp256",
				"scheme":  "ecdsa-sha2-nistp256",
				"key":     base64.StdEncoding.EncodeToString(der),
			},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/-/npm/v1/keys" {
			w.Write(keysJSON)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	c := &NPM{HTTP: srv.Client()}
	sigs := []npmSignature{{
		KeyID: keyID,
		Sig:   base64.StdEncoding.EncodeToString(sigDER),
	}}

	got := c.verifySignature(t.Context(), srv.URL, "pkg", "1.0.0", integrity, digest, sigs)
	if got != lockfile.EvidenceVerified {
		t.Fatalf("got %s, want verified", got)
	}

	unbound := c.verifySignature(t.Context(), srv.URL, "pkg", "1.0.0", integrity, "", sigs)
	if unbound != lockfile.EvidencePresent {
		t.Fatalf("unbound digest must stay present, got %s", unbound)
	}

	bad := c.verifySignature(t.Context(), srv.URL, "pkg", "1.0.0", integrity, digest, []npmSignature{{
		KeyID: keyID,
		Sig:   base64.StdEncoding.EncodeToString([]byte("not-a-sig")),
	}})
	if bad != lockfile.EvidencePresent {
		t.Fatalf("bad signature must stay present, got %s", bad)
	}

	if c.verifySignature(t.Context(), srv.URL, "pkg", "1.0.0", integrity, digest, nil) != lockfile.EvidenceMissing {
		t.Fatal("empty signatures must be missing")
	}
}

func TestParseRegistryKeysRejectsKeyIDMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{
				"keyid":   "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"keytype": "ecdsa-sha2-nistp256",
				"scheme":  "ecdsa-sha2-nistp256",
				"key":     base64.StdEncoding.EncodeToString(der),
			},
		},
	})
	keys, err := parseRegistryKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("mismatched keyid must be rejected: %#v", keys)
	}
}

func TestParseRegistryKeysRejectsEmptyKeyID(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{
				"keyid":   "",
				"keytype": "ecdsa-sha2-nistp256",
				"scheme":  "ecdsa-sha2-nistp256",
				"key":     base64.StdEncoding.EncodeToString(der),
			},
		},
	})
	keys, err := parseRegistryKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("empty keyid must be rejected: %#v", keys)
	}
}

func TestExtractChainVerifiedIgnoresPublishAttestation(t *testing.T) {
	// Provenance present via unsigned top-level predicate, plus a
	// non-provenance publish attestation bundle. Without a verifying
	// provenance bundle, state must stay present (not verified).
	raw := []byte(`{
		"attestations":[{
			"predicateType":"https://slsa.dev/provenance/v1",
			"predicate":{
				"buildDefinition":{
					"resolvedDependencies":[{
						"uri":"git+https://github.com/example/pkg",
						"digest":{"sha1":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
					}],
					"externalParameters":{"workflow":{"path":".github/workflows/release.yml"}}
				},
				"runDetails":{"builder":{"id":"https://github.com/actions/runner"}}
			}
		},{
			"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
			"bundle":{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}
		}]
	}`)
	state, chain := extractChainVerified(raw, "sha512:"+strings.Repeat("ab", 32))
	if state != lockfile.EvidencePresent {
		t.Fatalf("state = %s, want present", state)
	}
	if chain.State != lockfile.EvidencePresent {
		t.Fatalf("chain state = %s, want present", chain.State)
	}
}

func TestExtractChainVerifiedIgnoresMismatchedOuterType(t *testing.T) {
	// Outer envelope claims provenance but the only bundle is not a
	// verifiable provenance statement. Must not become verified.
	raw := []byte(`{
		"attestations":[{
			"predicateType":"https://slsa.dev/provenance/v1",
			"predicate":{"runDetails":{"builder":{"id":"https://evil.example/builder"}}},
			"bundle":{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsseEnvelope":{"payload":"e30="}}
		}]
	}`)
	state, chain := extractChainVerified(raw, "sha512:"+strings.Repeat("cd", 32))
	if state != lockfile.EvidencePresent {
		t.Fatalf("state = %s, want present", state)
	}
	if chain.State == lockfile.EvidenceVerified {
		t.Fatalf("chain must not be verified from unsigned outer predicate: %+v", chain)
	}
}
