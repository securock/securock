package credential_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/securock/securock/internal/credential"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplicitCredentialLifecycle(t *testing.T) {
	status := 200
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("credential missing")
		}
		if r.Method == "GET" {
			w.WriteHeader(status)
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/rotate") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"replacement-private-token"}`))
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		t.Error("unexpected mutation")
	}))
	defer s.Close()
	o := credential.Options{Provider: "gitlab", Action: "check", Origin: s.URL, Token: "fixture-token", Client: s.Client()}
	r, e := credential.Execute(context.Background(), o)
	if e != nil || r.State != "active" {
		t.Fatal(r, e)
	}
	status = 403
	r, e = credential.Execute(context.Background(), o)
	if e == nil || r.State != "unknown" {
		t.Fatal("permission denial called inactive")
	}
	status = 401
	r, e = credential.Execute(context.Background(), o)
	if e != nil || r.State != "inactive" {
		t.Fatal(r, e)
	}
	o.Action = "rotate"
	if _, e := credential.Execute(context.Background(), o); e == nil {
		t.Fatal("rotation without destination")
	}
	var replacement bytes.Buffer
	o.Replacement = &replacement
	r, e = credential.Execute(context.Background(), o)
	if e != nil || r.State != "rotated" || replacement.String() != "replacement-private-token\n" {
		t.Fatal(r, e)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "replacement-private-token") {
		t.Fatal("credential disclosed")
	}
	o.Action = "revoke"
	r, e = credential.Execute(context.Background(), o)
	if e != nil || r.State != "revoked" {
		t.Fatal(r, e)
	}
}
