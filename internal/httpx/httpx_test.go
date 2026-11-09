package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/securock/securock/internal/httpx"
)

func TestDoSameOriginRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/redir", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := httpx.Do(context.Background(), srv.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %s", res.Status)
	}
}

func TestDoRejectsCrossOriginRedirect(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	}))
	t.Cleanup(dest.Close)

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	t.Cleanup(src.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, src.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = httpx.Do(context.Background(), src.Client(), req)
	if err == nil || !strings.Contains(err.Error(), "cross-origin redirect") {
		t.Fatalf("expected cross-origin redirect error, got %v", err)
	}
}

func TestDoWithLimit(t *testing.T) {
	httpx.Configure(true, 0)
	t.Cleanup(func() { httpx.Configure(false, 0) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 3<<20))
	}))
	t.Cleanup(srv.Close)

	get := func(do func(*http.Request) (*http.Response, error)) error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := do(req)
		if err == nil {
			res.Body.Close()
		}
		return err
	}
	// Do keeps its cap: callers decide a package document is too large by it.
	if err := get(func(r *http.Request) (*http.Response, error) { return httpx.Do(context.Background(), srv.Client(), r) }); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("Do should reject a 3 MB response, got %v", err)
	}
	// The CISA KEV catalog is already close to 2 MB, so a feed needs a higher cap.
	if err := get(func(r *http.Request) (*http.Response, error) {
		return httpx.DoWithLimit(context.Background(), srv.Client(), r, 8<<20)
	}); err != nil {
		t.Fatalf("a 3 MB response should pass an 8 MB cap: %v", err)
	}
	if err := get(func(r *http.Request) (*http.Response, error) {
		return httpx.DoWithLimit(context.Background(), srv.Client(), r, 1<<20)
	}); err == nil {
		t.Fatal("a 3 MB response should fail a 1 MB cap")
	}
}
