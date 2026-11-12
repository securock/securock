package dast_test

import (
	"context"
	"encoding/json"
	"github.com/securock/securock/internal/dast"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatefulScenarioCookiesCapturesAndRedaction(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/api/login":
			if r.Method != "POST" {
				t.Error(r.Method)
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "private-session", HttpOnly: true})
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"item":"private-item"}`))
		case "/api/items/private-item":
			cookie, e := r.Cookie("session")
			if e != nil || cookie.Value != "private-session" {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	raw := `{"version":1,"steps":[{"id":"login","method":"POST","path":"/login","body_env":"LOGIN_BODY","content_type":"application/json","status":200,"capture":{"item":"/item"}},{"id":"read","method":"GET","path":"/items/{{item}}","status":204}]}`
	s, e := dast.ReadScenario(strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	env := func(string) string { return `{"password":"private-password"}` }
	if _, e = dast.RunScenario(context.Background(), server.URL+"/api", s, false, env, nil); e == nil || requests != 0 {
		t.Fatal("mutation preflight contacted the server", e, requests)
	}
	report, e := dast.RunScenario(context.Background(), server.URL+"/api", s, true, env, nil)
	if e != nil || len(report.Findings) != 0 || requests != 2 {
		t.Fatal(report, e, requests)
	}
	s.Steps[1].Status = 200
	report, e = dast.RunScenario(context.Background(), server.URL+"/api", s, true, env, nil)
	data, _ := json.Marshal(report)
	if e != nil || len(report.Findings) != 1 || report.Findings[0].ID != "dast:scenario-contract-violated" {
		t.Fatal(report, e)
	}
	for _, secret := range []string{"private-session", "private-item", "private-password"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("sensitive scenario data leaked")
		}
	}
}

func TestScenarioRejectsScopeEscapeBeforeRequests(t *testing.T) {
	for _, path := range []string{"//evil.test/a", "https://evil.test/a", "/../admin", "/%2e%2e/admin", "/x?token=secret", "/x#fragment"} {
		raw, _ := json.Marshal(map[string]any{"version": 1, "steps": []any{map[string]any{"id": "read", "method": "GET", "path": path, "status": 200}}})
		if _, e := dast.ReadScenario(strings.NewReader(string(raw))); e == nil {
			t.Fatalf("accepted %s", path)
		}
	}
}
