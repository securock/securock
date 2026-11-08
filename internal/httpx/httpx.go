package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxBody    = 2 << 20
	retries    = 3
	defaultTTL = time.Hour
	cacheName  = "securock"
)

var (
	cacheMu       sync.RWMutex
	cacheDisabled bool
	cacheTTL      = defaultTTL
)

// Configure sets how responses are cached on disk for the rest of the process. Disabled
// neither reads nor writes the cache. A ttl of zero or less means the default of one hour.
func Configure(disabled bool, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	cacheMu.Lock()
	cacheDisabled, cacheTTL = disabled, ttl
	cacheMu.Unlock()
}

func cacheSettings() (disabled bool, ttl time.Duration) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return cacheDisabled, cacheTTL
}

// cacheable says whether a response to this request may be stored. The cache is shared by
// every request the user makes, so anything that carries credentials stays out of it.
func cacheable(req *http.Request) bool {
	if disabled, _ := cacheSettings(); disabled {
		return false
	}
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return false
	}
	for _, h := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		if req.Header.Get(h) != "" {
			return false
		}
	}
	return true
}

func CacheDir() string {
	root, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), cacheName)
	}
	return filepath.Join(root, cacheName)
}

func Do(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	c := *client
	parent := client.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := sameOriginRedirect(req, via); err != nil {
			return err
		}
		if parent != nil {
			return parent(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}

	key := cacheKey(req)
	useCache := cacheable(req)
	if useCache {
		if raw, ok := readCache(key); ok {
			return cachedResponse(req, raw), nil
		}
	}

	var last error
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(100<<attempt) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
		}
		res, err := c.Do(req.Clone(ctx))
		if err != nil {
			last = err
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
		res.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if len(raw) > maxBody {
			return nil, fmt.Errorf("response too large")
		}
		if res.StatusCode >= 500 {
			last = fmt.Errorf("unexpected status %s", res.Status)
			continue
		}
		if useCache && res.StatusCode == http.StatusOK {
			writeCache(key, raw)
		}
		res.Body = io.NopCloser(bytes.NewReader(raw))
		res.ContentLength = int64(len(raw))
		return res, nil
	}
	if last == nil {
		last = fmt.Errorf("request failed")
	}
	return nil, last
}

func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || req.URL == nil {
		return nil
	}
	orig := via[0].URL
	if orig == nil {
		return nil
	}
	if req.URL.Scheme != orig.Scheme || !strings.EqualFold(req.URL.Host, orig.Host) {
		return fmt.Errorf("refusing cross-origin redirect from %s to %s", orig, req.URL)
	}
	return nil
}

func cacheKey(req *http.Request) string {
	var buf bytes.Buffer
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.URL.String())
	// The same URL can answer differently to a different Accept.
	buf.WriteString(" accept=" + req.Header.Get("Accept"))
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err == nil {
			raw, _ := io.ReadAll(io.LimitReader(body, maxBody))
			buf.Write(raw)
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func cachePath(key string) string {
	return filepath.Join(CacheDir(), key)
}

func readCache(key string) ([]byte, bool) {
	_, ttl := cacheSettings()
	path := cachePath(key)
	st, err := os.Stat(path)
	if err != nil || time.Since(st.ModTime()) > ttl {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// writeCache stores the response under a temporary name and renames it into place, so a
// reader running at the same time, such as another goroutine or another securock process,
// sees the whole response or none of it, never half of one. Failure is not an error: the
// cache only saves time.
func writeCache(key string, raw []byte) {
	dir := CacheDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), cachePath(key)) != nil {
		_ = os.Remove(tmp.Name())
	}
}

const tempPrefix = ".tmp-"

var cacheEntry = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Clear deletes the cached responses and returns how many it removed. It only touches
// files securock wrote, so a cache directory that is shared by mistake keeps its other files.
func Clear() (int, error) {
	entries, err := os.ReadDir(CacheDir())
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(cacheEntry.MatchString(name) || strings.HasPrefix(name, tempPrefix)) {
			continue
		}
		if err := os.Remove(filepath.Join(CacheDir(), name)); err != nil {
			return removed, err
		}
		if cacheEntry.MatchString(name) {
			removed++
		}
	}
	return removed, nil
}

func cachedResponse(req *http.Request, raw []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Body:          io.NopCloser(bytes.NewReader(raw)),
		ContentLength: int64(len(raw)),
		Header:        make(http.Header),
		Request:       req,
	}
}
