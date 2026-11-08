package httpx_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securock/securock/internal/httpx"
)

// isolate points the cache at a fresh directory and restores the default settings after.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LocalAppData", dir)
	httpx.Configure(false, 0)
	t.Cleanup(func() { httpx.Configure(false, 0) })
}

func get(t *testing.T, url string, header map[string]string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := httpx.Do(context.Background(), nil, req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func countingServer(t *testing.T, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(body + r.Header.Get("Accept")))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func cacheFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(httpx.CacheDir())
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestCacheServesRepeatRequests(t *testing.T) {
	isolate(t)
	srv, hits := countingServer(t, "answer")
	for range 3 {
		if got := get(t, srv.URL, nil); got != "answer" {
			t.Fatalf("body = %q", got)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("server was asked %d times, want 1", hits.Load())
	}
}

func TestNoCacheNeitherReadsNorWrites(t *testing.T) {
	isolate(t)
	srv, hits := countingServer(t, "answer")
	get(t, srv.URL, nil) // fills the cache
	httpx.Configure(true, 0)
	get(t, srv.URL, nil)
	get(t, srv.URL, nil)
	if hits.Load() != 3 {
		t.Fatalf("with the cache off every request must reach the server, got %d", hits.Load())
	}

	isolate(t)
	httpx.Configure(true, 0)
	srv2, _ := countingServer(t, "x")
	get(t, srv2.URL, nil)
	if files := cacheFiles(t); len(files) != 0 {
		t.Fatalf("nothing may be written with the cache off: %v", files)
	}
}

func TestCacheTTL(t *testing.T) {
	isolate(t)
	httpx.Configure(false, 20*time.Millisecond)
	srv, hits := countingServer(t, "answer")
	get(t, srv.URL, nil)
	get(t, srv.URL, nil)
	if hits.Load() != 1 {
		t.Fatalf("a fresh entry must be used, hits = %d", hits.Load())
	}
	time.Sleep(60 * time.Millisecond)
	get(t, srv.URL, nil)
	if hits.Load() != 2 {
		t.Fatalf("an expired entry must be fetched again, hits = %d", hits.Load())
	}
}

func TestRequestsWithCredentialsAreNotCached(t *testing.T) {
	isolate(t)
	srv, hits := countingServer(t, "private")
	for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		get(t, srv.URL, map[string]string{h: "secret"})
		get(t, srv.URL, map[string]string{h: "secret"})
	}
	if hits.Load() != 6 {
		t.Fatalf("hits = %d, want 6", hits.Load())
	}
	if files := cacheFiles(t); len(files) != 0 {
		t.Fatalf("a response to an authenticated request was stored: %v", files)
	}
}

func TestCacheKeyIncludesAccept(t *testing.T) {
	isolate(t)
	srv, hits := countingServer(t, "body:")
	a := get(t, srv.URL, map[string]string{"Accept": "application/a"})
	b := get(t, srv.URL, map[string]string{"Accept": "application/b"})
	if a == b || hits.Load() != 2 {
		t.Fatalf("different Accept must not share an entry: %q %q hits=%d", a, b, hits.Load())
	}
}

func TestCacheFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	isolate(t)
	srv, _ := countingServer(t, "answer")
	get(t, srv.URL, nil)
	info, err := os.Stat(httpx.CacheDir())
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir: %v, %v", info, err)
	}
	for _, name := range cacheFiles(t) {
		st, err := os.Stat(filepath.Join(httpx.CacheDir(), name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v", name, st, err)
		}
	}
}

// Readers that run while a response is being stored must never see part of it, and no
// temporary file may be left behind.
func TestCacheWritesAreAtomic(t *testing.T) {
	isolate(t)
	body := strings.Repeat("0123456789abcdef", 1<<14)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if got := get(t, srv.URL, nil); got != body {
					errs <- "short or corrupt body"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	for _, name := range cacheFiles(t) {
		if strings.HasPrefix(name, ".tmp-") {
			t.Fatalf("temporary file left behind: %s", name)
		}
	}
}

func TestClear(t *testing.T) {
	isolate(t)
	if n, err := httpx.Clear(); err != nil || n != 0 {
		t.Fatalf("clearing a cache that does not exist: %d, %v", n, err)
	}
	srvA, _ := countingServer(t, "a")
	srvB, _ := countingServer(t, "b")
	get(t, srvA.URL, nil)
	get(t, srvB.URL, nil)
	foreign := filepath.Join(httpx.CacheDir(), "notes.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := httpx.Clear()
	if err != nil || n != 2 {
		t.Fatalf("removed %d, err %v", n, err)
	}
	if raw, err := os.ReadFile(foreign); err != nil || !bytes.Equal(raw, []byte("keep")) {
		t.Fatal("a file securock did not write was removed")
	}
}
