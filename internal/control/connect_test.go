package control_test

import (
	"context"
	"encoding/json"
	"github.com/securock/securock/internal/control"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOutboxDeliveryAndRemoteStatus(t *testing.T) {
	s, token, _ := fixture(t)
	count := 0
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing credential")
		}
		count++
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			if r.URL.Path != "/repos/acme/repo/issues" {
				t.Error(r.URL.Path)
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["title"] != "fix" {
				t.Error(body)
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"number":42,"state":"open"}`))
		} else {
			_, _ = w.Write([]byte(`{"number":42,"state":"closed"}`))
		}
	}))
	defer remote.Close()
	t.Setenv("CONNECTOR_FIXTURE_TOKEN", "fixture-token")
	s.Connectors = []control.Connector{{ID: "github", Tenant: "a", Provider: "github", Origin: remote.URL, Project: "acme/repo", TokenEnv: "CONNECTOR_FIXTURE_TOKEN"}}
	s.DeliveryClient = remote.Client()
	if e := control.ValidateConnectors(s.Connectors); e != nil {
		t.Fatal(e)
	}
	body := `{"id":"finding","connector":"github","kind":"issue","title":"fix","body":"redacted evidence"}`
	if w := request(s, token("alice"), "POST", "/api/v1/deliveries", body); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if e := s.Dispatch(context.Background()); e != nil {
		t.Fatal(e)
	}
	request(s, token("alice"), "POST", "/api/v1/deliveries", body)
	if e := s.Dispatch(context.Background()); e != nil {
		t.Fatal(e)
	}
	if count != 1 {
		t.Fatal("duplicate create")
	}
	_ = s.Store.Update(func(st *control.State) error {
		d := st.Tenants["a"].Deliveries["finding"]
		d.Next = ""
		st.Tenants["a"].Deliveries["finding"] = d
		return nil
	})
	if e := s.Dispatch(context.Background()); e != nil {
		t.Fatal(e)
	}
	d := s.Store.Read().Tenants["a"].Deliveries["finding"]
	if d.RemoteID != "42" || d.RemoteState != "closed" {
		t.Fatal(d)
	}
	if request(s, token("bob"), "GET", "/api/v1/deliveries", "").Body.String() == request(s, token("alice"), "GET", "/api/v1/deliveries", "").Body.String() {
		t.Fatal("outbox tenant leak")
	}
}
