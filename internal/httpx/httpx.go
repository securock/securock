package httpx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	maxBody   = 2 << 20
	retries   = 3
	cacheTTL  = time.Hour
	cacheName = "securock"
)

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

	key := cacheKey(req)
	if req.Method == http.MethodGet || req.Method == http.MethodPost {
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
		res, err := client.Do(req.Clone(ctx))
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
		if req.Method == http.MethodGet || req.Method == http.MethodPost {
			if res.StatusCode == http.StatusOK {
				writeCache(key, raw)
			}
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

func cacheKey(req *http.Request) string {
	var buf bytes.Buffer
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.URL.String())
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
	path := cachePath(key)
	st, err := os.Stat(path)
	if err != nil || time.Since(st.ModTime()) > cacheTTL {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func writeCache(key string, raw []byte) {
	dir := CacheDir()
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(cachePath(key), raw, 0o644)
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
