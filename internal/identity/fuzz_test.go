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

func FuzzVerifyAccessToken(f *testing.F) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		f.Fatal(e)
	}
	enc := base64.RawURLEncoding.EncodeToString
	config := identity.Config{Issuer: "https://id.example", Audience: "api", Keys: []identity.Key{{Kty: "RSA", Kid: "fixture", N: enc(key.N.Bytes()), E: enc(big.NewInt(int64(key.E)).Bytes())}}, Bindings: []identity.Binding{{Subject: "alice", Tenant: "acme", Roles: []string{"developer"}}}}
	claims, _ := json.Marshal(map[string]any{"iss": config.Issuer, "aud": "api", "sub": "alice", "exp": 3000})
	message := enc([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + enc(claims)
	sum := sha256.Sum256([]byte(message))
	sig, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if e != nil {
		f.Fatal(e)
	}
	f.Add(message + "." + enc(sig))
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		p, e := config.Verify(token, time.Unix(2000, 0))
		if e == nil && (p.Subject != "alice" || p.Tenant != "acme" || p.Can("approve") || !p.Can("scan")) {
			t.Fatal("verified token escaped its configured binding")
		}
	})
}
