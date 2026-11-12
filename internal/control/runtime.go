package control

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"net"
	"net/http"
	"strings"
	"time"
)

type bucket struct {
	Start time.Time
	Count int
}
type response struct {
	http.ResponseWriter
	Status int
}

func (w *response) WriteHeader(status int) {
	if w.Status != 0 {
		return
	}
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *response) Write(p []byte) (int, error) {
	if w.Status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(p)
}
func (s *Server) permit(key string, limit int) bool {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.buckets == nil {
		s.buckets = map[string]bucket{}
	}
	now := time.Now()
	b := s.buckets[key]
	if b.Start.IsZero() || now.Sub(b.Start) >= time.Minute {
		if len(s.buckets) >= 4096 {
			for k, v := range s.buckets {
				if now.Sub(v.Start) >= time.Minute {
					delete(s.buckets, k)
				}
			}
			if len(s.buckets) >= 4096 {
				return false
			}
		}
		b = bucket{Start: now}
	}
	if b.Count >= limit {
		return false
	}
	b.Count++
	s.buckets[key] = b
	return true
}
func peer(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || net.ParseIP(host) == nil {
		return "unknown"
	}
	return host
}
func route(path string) string {
	for _, exact := range []string{"/", "/ui", "/healthz", "/auth/login", "/auth/callback", "/auth/logout", "/api/v1/me", "/api/v1/projects", "/api/v1/jobs", "/api/v1/issues", "/api/v1/connectors", "/api/v1/approvals", "/api/v1/audit", "/api/v1/metrics", "/api/v1/retention", "/api/v1/export", "/api/v1/deliveries", "/api/v1/runner/claim", "/api/v1/runner/complete", "/scim/v2/Users"} {
		if path == exact {
			return exact
		}
	}
	for _, prefix := range []string{"/api/v1/jobs/", "/api/v1/issues/", "/api/v1/approvals/", "/api/v1/deliveries/", "/scim/v2/Users/"} {
		if strings.HasPrefix(path, prefix) {
			return prefix + ":id"
		}
	}
	return "/unknown"
}
func (s *Server) access(r *http.Request, status int, p identity.Principal) {
	if s.AccessLog == nil {
		return
	}
	method := r.Method
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		method = "OTHER"
	}
	raw, _ := json.Marshal(map[string]any{"time": UTC(), "method": method, "route": route(r.URL.Path), "status": status, "peer_ip": peer(r), "subject": p.Subject, "tenant": p.Tenant})
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	_, _ = fmt.Fprintln(s.AccessLog, string(raw))
}
func (s *Store) Bindings() []identity.Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []identity.Binding{}
	for tenant, t := range s.state.Tenants {
		for _, m := range t.Members {
			if m.Active {
				out = append(out, identity.Binding{Subject: m.Subject, Tenant: tenant, Roles: append([]string(nil), m.Roles...)})
			}
		}
	}
	return out
}
