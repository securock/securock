package dast_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securock/securock/internal/dast"
	"github.com/securock/securock/internal/finding"
)

func ids(r finding.Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Findings {
		out[f.ID] = true
	}
	return out
}

func TestHTTPFindingsAndNoCredentialValues(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request: %v", r)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Set-Cookie", "session=private-cookie-value; SameSite=None")
		w.Write([]byte(`<a href="/do-not-crawl">next</a>`))
	}))
	defer srv.Close()
	report, err := dast.Scan(context.Background(), dast.Options{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(report)
	for _, id := range []string{"unencrypted-http", "csp-missing", "frame-protection-missing", "nosniff-missing", "referrer-policy-missing", "cookie-secure-missing", "cookie-httponly-missing", "cookie-samesite-none-insecure"} {
		if !got["dast:"+id] {
			t.Errorf("missing %s: %+v", id, report)
		}
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "private-cookie-value") {
		t.Fatal("cookie value leaked")
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected crawling: %d requests", requests.Load())
	}
}

func TestHardenedTLSAndCertificateVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "not-for-reports", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}))
	defer srv.Close()
	report, err := dast.Scan(context.Background(), dast.Options{URL: srv.URL, Client: srv.Client()})
	if err != nil || len(report.Findings) != 0 {
		t.Fatalf("hardened response: %+v, %v", report, err)
	}
	report, err = dast.Scan(context.Background(), dast.Options{URL: srv.URL})
	if err == nil || !ids(report)["dast:analysis-incomplete"] {
		t.Fatalf("untrusted TLS must fail: %+v, %v", report, err)
	}
}

func TestRedirectsStayInScopeAndDoNotReplayCookies(t *testing.T) {
	var outsideHits atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1) }))
	defer outside.Close()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Cookie") != "" {
			t.Error("replayed cookie")
		}
		switch r.URL.Path {
		case "/start":
			w.Header().Add("Set-Cookie", "session=hidden")
			http.Redirect(w, r, "/end", 302)
		case "/end":
			w.Header().Set("Content-Type", "application/json")
		case "/outside":
			http.Redirect(w, r, outside.URL, 302)
		default:
			http.Redirect(w, r, "/loop", 302)
		}
	}))
	defer srv.Close()
	report, err := dast.Scan(context.Background(), dast.Options{URL: srv.URL + "/start"})
	if err != nil || hits.Load() != 2 || !ids(report)["dast:cookie-secure-missing"] {
		t.Fatalf("redirect findings lost: %+v, %v, hits %d", report, err, hits.Load())
	}
	_, err = dast.Scan(context.Background(), dast.Options{URL: srv.URL + "/outside"})
	if err == nil || outsideHits.Load() != 0 {
		t.Fatalf("cross-origin redirect followed: %d, %v", outsideHits.Load(), err)
	}
	hits.Store(0)
	_, err = dast.Scan(context.Background(), dast.Options{URL: srv.URL + "/loop"})
	if err == nil || hits.Load() != 6 {
		t.Fatalf("redirect budget not enforced: %d, %v", hits.Load(), err)
	}
}

func TestFailuresAreNotCleanScans(t *testing.T) {
	for _, status := range []int{401, 403, 404, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer srv.Close()
			report, err := dast.Scan(context.Background(), dast.Options{URL: srv.URL})
			if err == nil || !ids(report)["dast:analysis-incomplete"] {
				t.Fatalf("failure reported clean: %+v %v", report, err)
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	report, err := dast.Scan(context.Background(), dast.Options{URL: srv.URL, Timeout: 20 * time.Millisecond})
	if err == nil || !ids(report)["dast:analysis-incomplete"] {
		t.Fatalf("timeout reported clean: %+v %v", report, err)
	}
}

func TestHeaderRules(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    []string
		absent  []string
	}{
		{"JSON does not need HTML defenses", map[string]string{"Content-Type": "application/json"}, nil, []string{"csp-missing", "frame-protection-missing"}},
		{"report-only is not enforced", map[string]string{"Content-Type": "text/html", "Content-Security-Policy-Report-Only": "default-src 'self'"}, []string{"csp-missing", "frame-protection-missing"}, nil},
		{"invalid frame option", map[string]string{"Content-Type": "text/html", "X-Frame-Options": "ALLOWALL"}, []string{"frame-protection-missing"}, nil},
		{"wildcard framing is unrestricted", map[string]string{"Content-Type": "text/html", "Content-Security-Policy": "frame-ancestors *"}, []string{"frame-protection-missing"}, nil},
		{"restricted wildcard framing origin", map[string]string{"Content-Type": "text/html", "Content-Security-Policy": "frame-ancestors https://*.example.com"}, nil, []string{"frame-protection-missing"}},
		{"valid frame option", map[string]string{"Content-Type": "text/html", "X-Frame-Options": "SAMEORIGIN"}, nil, []string{"frame-protection-missing"}},
		{"HSTS disabled", map[string]string{"Strict-Transport-Security": "max-age=0"}, []string{"hsts-missing"}, nil},
		{"HSTS malformed", map[string]string{"Strict-Transport-Security": "max-age=oops"}, []string{"hsts-missing"}, nil},
		{"CSP framing directive", map[string]string{"Content-Type": "text/html", "Content-Security-Policy": "frame-ancestors 'none'"}, nil, []string{"frame-protection-missing"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.headers {
					w.Header().Set(k, v)
				}
			}))
			defer srv.Close()
			report, err := dast.Scan(context.Background(), dast.Options{URL: srv.URL, Client: srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			got := ids(report)
			for _, id := range tt.want {
				if !got["dast:"+id] {
					t.Errorf("missing %s", id)
				}
			}
			for _, id := range tt.absent {
				if got["dast:"+id] {
					t.Errorf("unexpected %s", id)
				}
			}
		})
	}
}

func TestInvalidTargets(t *testing.T) {
	for _, target := range []string{"", "example.com", "file:///etc/passwd", "ftp://host/", "https://user:password@host/", "https://host/?token=secret", "https://host/#fragment", "http://host:0/", "http://host:99999/", "http://host:invalid/"} {
		if _, err := dast.ValidateURL(target); err == nil {
			t.Errorf("accepted %q", target)
		}
	}
}
