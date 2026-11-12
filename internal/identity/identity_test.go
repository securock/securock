package identity_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/securock/securock/internal/identity"
	"math/big"
	"testing"
	"time"
)

func TestVerification(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	enc := base64.RawURLEncoding.EncodeToString
	c := identity.Config{Issuer: "https://id.example", Audience: "securock", Keys: []identity.Key{{Kty: "RSA", Kid: "a", N: enc(k.N.Bytes()), E: enc(big.NewInt(int64(k.E)).Bytes())}}, Bindings: []identity.Binding{{Subject: "alice", Tenant: "acme", Roles: []string{"developer"}}}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	now := time.Unix(2000, 0)
	sign := func(alg, issuer, aud string, exp int64) string {
		h, _ := json.Marshal(map[string]any{"alg": alg, "kid": "a"})
		b, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "alice", "aud": aud, "exp": exp})
		s := enc(h) + "." + enc(b)
		d := sha256.Sum256([]byte(s))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		return s + "." + enc(sig)
	}
	for _, tc := range []struct {
		alg, iss, aud string
		exp           int64
		ok            bool
	}{{"RS256", c.Issuer, c.Audience, 2100, true}, {"none", c.Issuer, c.Audience, 2100, false}, {"RS256", "https://evil", c.Audience, 2100, false}, {"RS256", c.Issuer, "other", 2100, false}, {"RS256", c.Issuer, c.Audience, 2000, false}} {
		p, e := c.Verify(sign(tc.alg, tc.iss, tc.aud, tc.exp), now)
		if (e == nil) != tc.ok {
			t.Fatalf("%+v: %v", tc, e)
		}
		if tc.ok && (!p.Can("scan") || p.Can("approve") || p.Tenant != "acme") {
			t.Fatal(p)
		}
	}
}
