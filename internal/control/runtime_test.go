package control_test

import (
	"bytes"
	"strings"
	"testing"
)

func TestServiceLimitsAndRedactedRequestLogs(t *testing.T) {
	s, token, _ := fixture(t)
	s.RequestsPerMinute = 1
	var log bytes.Buffer
	s.AccessLog = &log
	a := token("alice")
	w := request(s, a, "GET", "/api/v1/jobs/sensitive-object?credential=private-query", "")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	w = request(s, a, "GET", "/api/v1/me", "")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("subject limit missing")
	}
	if request(s, "", "GET", "/healthz", "").Code != 200 {
		t.Fatal("health probe rate limited")
	}
	raw := log.String()
	for _, secret := range []string{"sensitive-object", "private-query", a} {
		if strings.Contains(raw, secret) {
			t.Fatal("request log disclosed sensitive input")
		}
	}
	if !strings.Contains(raw, "/api/v1/jobs/:id") || !strings.Contains(raw, "alice") {
		t.Fatal(raw)
	}
}
