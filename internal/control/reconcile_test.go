package control_test

import (
	"context"
	"github.com/securock/securock/internal/control"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUncertainIssueReconciliationRequiresRemoteMarker(t *testing.T) {
	s, token, _ := fixture(t)
	marker := false
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if marker {
			_, _ = w.Write([]byte(`{"number":42,"state":"closed","body":"securock-delivery:lost"}`))
		} else {
			_, _ = w.Write([]byte(`{"number":42,"state":"closed","body":"unrelated issue"}`))
		}
	}))
	defer remote.Close()
	t.Setenv("RECONCILE_TOKEN", "fixture")
	s.Connectors = []control.Connector{{ID: "github", Tenant: "a", Provider: "github", Origin: remote.URL, Project: "acme/repo", TokenEnv: "RECONCILE_TOKEN"}}
	s.DeliveryClient = remote.Client()
	request(s, token("alice"), "POST", "/api/v1/deliveries", `{"id":"lost","connector":"github","kind":"issue","title":"fix","body":"redacted evidence"}`)
	if e := s.Dispatch(context.Background()); e != nil {
		t.Fatal(e)
	}
	for _, valid := range []bool{false, true} {
		marker = valid
		if w := request(s, token("alice"), "POST", "/api/v1/deliveries/lost/reconcile", `{"remote_id":"42"}`); w.Code != 202 {
			t.Fatal(w.Body.String())
		}
		if e := s.Dispatch(context.Background()); e != nil {
			t.Fatal(e)
		}
		d := s.Store.Read().Tenants["a"].Deliveries["lost"]
		if valid && d.Status != "delivered" || !valid && d.Status != "uncertain" {
			t.Fatal(d)
		}
	}
}
