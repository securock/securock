package control_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/identity"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*control.Server, func(string) string, string) {
	t.Helper()
	key := bytes.Repeat([]byte{7}, 32)
	dir := t.TempDir()
	bindings := []identity.Binding{{Subject: "alice", Tenant: "a", Roles: []string{"admin"}}, {Subject: "bob", Tenant: "b", Roles: []string{"admin"}}, {Subject: "dev", Tenant: "a", Roles: []string{"developer"}}, {Subject: "robot", Tenant: "a", Roles: []string{"runner"}}}
	s, e := control.Open(dir, key, bindings)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	enc := base64.RawURLEncoding.EncodeToString
	id := identity.Config{Issuer: "https://id.example", Audience: "api", Keys: []identity.Key{{Kty: "RSA", Kid: "k", N: enc(k.N.Bytes()), E: enc(big.NewInt(int64(k.E)).Bytes())}}, Bindings: bindings}
	sign := func(sub string) string {
		h := enc([]byte(`{"alg":"RS256","kid":"k"}`))
		b, _ := json.Marshal(map[string]any{"iss": id.Issuer, "aud": id.Audience, "sub": sub, "exp": time.Now().Unix() + 3600})
		msg := h + "." + enc(b)
		sum := sha256.Sum256([]byte(msg))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		return msg + "." + enc(sig)
	}
	return &control.Server{Store: s, Identity: id}, sign, dir
}
func request(s *control.Server, token, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestIsolationPersistenceAndSCIM(t *testing.T) {
	s, token, dir := fixture(t)
	a, b := token("alice"), token("bob")
	if request(s, "", "GET", "/api/v1/projects", "").Code != 401 {
		t.Fatal("anonymous access")
	}
	if w := request(s, a, "POST", "/api/v1/projects", `{"id":"repo","name":"private","owner":"team"}`); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	request(s, a, "POST", "/api/v1/jobs", `{"id":"job","project":"repo"}`)
	if request(s, b, "GET", "/api/v1/jobs/job", "").Code != 404 {
		t.Fatal("tenant leak")
	}
	if strings.Contains(request(s, b, "GET", "/api/v1/projects", "").Body.String(), "private") {
		t.Fatal("tenant list leak")
	}
	if request(s, token("robot"), "POST", "/api/v1/projects", `{"id":"bad","name":"bad"}`).Code != 403 {
		t.Fatal("runner escalation")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.enc"))
	if bytes.Contains(raw, []byte("private")) {
		t.Fatal("plaintext state")
	}
	if _, e := control.Open(dir, bytes.Repeat([]byte{7}, 32), nil); e == nil {
		t.Fatal("concurrent open")
	}
	members := s.Store.Read().Tenants["a"].Members
	id := members["dev"].ID
	w := request(s, a, "PATCH", "/scim/v2/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if request(s, token("dev"), "GET", "/api/v1/projects", "").Code != 401 {
		t.Fatal("deactivated access")
	}
	_ = s.Store.Close()
	restored, e := control.Open(dir, bytes.Repeat([]byte{7}, 32), s.Identity.Bindings)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	if restored.Read().Tenants["a"].Members["dev"].Active {
		t.Fatal("restart reactivated member")
	}
	_ = restored.Close()
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(filepath.Join(dir, "state.enc"), raw, 0600)
	if _, e := control.Open(dir, bytes.Repeat([]byte{7}, 32), nil); e == nil {
		t.Fatal("tamper accepted")
	}
}
