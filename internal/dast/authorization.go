package dast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
)

type Actor struct {
	ID        string `json:"id"`
	BearerEnv string `json:"bearer_env"`
	Anonymous bool   `json:"anonymous"`
}
type AuthCase struct {
	ID       string          `json:"id"`
	Path     string          `json:"path"`
	Allow    []string        `json:"allow"`
	Deny     []string        `json:"deny"`
	Pointer  string          `json:"pointer"`
	Expected json.RawMessage `json:"expected"`
}
type Matrix struct {
	Version int        `json:"version"`
	Actors  []Actor    `json:"actors"`
	Cases   []AuthCase `json:"cases"`
}

func ReadMatrix(r io.Reader) (Matrix, error) {
	var m Matrix
	raw, e := io.ReadAll(io.LimitReader(r, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return m, fmt.Errorf("authorization matrix exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.Version != 1 || len(m.Actors) < 2 || len(m.Actors) > 20 || len(m.Cases) == 0 || len(m.Cases) > 200 {
		return m, fmt.Errorf("invalid authorization matrix")
	}
	actors := map[string]bool{}
	for _, a := range m.Actors {
		if a.ID == "" || actors[a.ID] || a.Anonymous == (a.BearerEnv != "") {
			return m, fmt.Errorf("invalid actor")
		}
		actors[a.ID] = true
	}
	ids := map[string]bool{}
	for _, c := range m.Cases {
		u, e := url.Parse(c.Path)
		if c.ID == "" || ids[c.ID] || e != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(c.Path, "/") || strings.Contains(c.Path, "..") || u.RawPath != "" || len(c.Allow) == 0 || len(c.Deny) == 0 || !strings.HasPrefix(c.Pointer, "/") || len(c.Expected) == 0 || !json.Valid(c.Expected) {
			return m, fmt.Errorf("invalid authorization case")
		}
		ids[c.ID] = true
		seen := map[string]bool{}
		for _, id := range append(slices.Clone(c.Allow), c.Deny...) {
			if !actors[id] || seen[id] {
				return m, fmt.Errorf("unknown, duplicate or overlapping actor")
			}
			seen[id] = true
		}
	}
	return m, nil
}
func pointer(raw []byte, path string) (any, bool) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil, false
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		key := strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		object, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return v, true
}

// Authorization tests explicit read-only role/object contracts. Bodies never enter reports.
func Authorization(ctx context.Context, origin string, m Matrix, getenv func(string) string, client *http.Client) (finding.Report, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	u, e := ValidateURL(origin)
	if e != nil {
		return finding.New("dast", nil), e
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && (ip == nil || !ip.IsLoopback()) {
		return finding.New("dast", nil), fmt.Errorf("authorization credentials require HTTPS")
	}
	tokens := map[string]string{}
	seen := map[string]bool{}
	for _, a := range m.Actors {
		if !a.Anonymous {
			token := getenv(a.BearerEnv)
			if token == "" || strings.ContainsAny(token, "\r\n") || seen[token] {
				return finding.New("dast", nil), fmt.Errorf("actor credentials missing, invalid or identical")
			}
			tokens[a.ID] = token
			seen[token] = true
		}
	}
	h := &http.Client{Timeout: 15 * time.Second}
	if client != nil {
		*h = *client
	}
	h.Jar = nil
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	found := []finding.Finding{}
	incomplete := false
	add := func(id, title, subject string) {
		found = append(found, finding.Finding{ID: "dast:" + id, Severity: finding.SeverityHigh, Title: title, Subject: subject, Remediation: "Enforce server-side object and role authorization; rerun the same test contract."})
	}
	for _, c := range m.Cases {
		target := *u
		target.Path = c.Path
		prefix := strings.TrimRight(u.Path, "/")
		if prefix != "" && c.Path != prefix && !strings.HasPrefix(c.Path, prefix+"/") {
			return finding.New("dast", found), fmt.Errorf("authorization path leaves explicit base path")
		}
		get := func(actor string) (int, []byte, error) {
			req, e := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
			if e != nil {
				return 0, nil, e
			}
			if tokens[actor] != "" {
				req.Header.Set("Authorization", "Bearer "+tokens[actor])
			}
			req.Header.Set("User-Agent", "securock-authorization")
			resp, e := h.Do(req)
			if e != nil {
				return 0, nil, fmt.Errorf("request failed")
			}
			defer resp.Body.Close()
			body, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
			if e != nil || len(body) > 65536 {
				return 0, nil, fmt.Errorf("response exceeds limit")
			}
			return resp.StatusCode, body, nil
		}
		controls := true
		var expected any
		_ = json.Unmarshal(c.Expected, &expected)
		for _, actor := range c.Allow {
			status, body, e := get(actor)
			value, ok := pointer(body, c.Pointer)
			if e != nil || status < 200 || status >= 300 || !ok || !reflect.DeepEqual(value, expected) {
				controls = false
				incomplete = true
				add("authorization-incomplete", "Allowed actor control response could not be validated", c.ID+":"+actor)
			}
		}
		if !controls {
			continue
		}
		for _, actor := range c.Deny {
			status, _, e := get(actor)
			if e != nil || status != 401 && status != 403 && status != 404 && (status < 200 || status >= 300) {
				incomplete = true
				add("authorization-incomplete", "Denied actor response was inconclusive", c.ID+":"+actor)
			} else if status >= 200 && status < 300 {
				add("authorization-bypass", "Actor received success for an explicitly forbidden object or role", c.ID+":"+actor)
			}
		}
	}
	if incomplete {
		return finding.New("dast", found), fmt.Errorf("authorization coverage incomplete")
	}
	return finding.New("dast", found), nil
}
