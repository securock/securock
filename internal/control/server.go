package control

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type Server struct {
	Connectors     []Connector
	DeliveryClient *http.Client
	Store          *Store
	Identity       identity.Config
}

func (s *Server) principal(r *http.Request) (identity.Principal, error) {
	c := s.Identity
	c.Bindings = nil
	for tenant, t := range s.Store.Read().Tenants {
		for _, m := range t.Members {
			if m.Active {
				c.Bindings = append(c.Bindings, identity.Binding{Subject: m.Subject, Tenant: tenant, Roles: m.Roles})
			}
		}
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return identity.Principal{}, fmt.Errorf("authentication required")
	}
	return c.Verify(strings.TrimPrefix(header, "Bearer "), time.Now())
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "data": v})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("one JSON value required")
	}
	return nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		reply(w, 200, map[string]string{"status": "ready"})
		return
	}
	if (r.URL.Path == "/ui" || r.URL.Path == "/") && r.Method == "GET" {
		console(w)
		return
	}
	if r.URL.Path == "/unused-index" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><html lang="en"><title>Securock control plane</title><h1>Securock control plane</h1><p>Authenticated API: /api/v1/me, /api/v1/projects, /api/v1/jobs</p><p>Use an OIDC API access token. Customer data is never shown without authentication.</p></html>`)
		return
	}
	p, e := s.principal(r)
	if e != nil {
		reply(w, 401, map[string]string{"error": "authentication required"})
		return
	}
	if s.opsAPI(w, r, p) {
		return
	}
	if s.deliveryAPI(w, r, p) {
		return
	}
	if s.runnerAPI(w, r, p) {
		return
	}
	if s.auditAPI(w, r, p) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/scim/v2/") {
		s.scim(w, r, p)
		return
	}
	if r.URL.Path == "/api/v1/me" && r.Method == "GET" {
		reply(w, 200, p)
		return
	}
	if !p.Can("read") {
		reply(w, 403, nil)
		return
	}
	if r.URL.Path == "/api/v1/projects" {
		if r.Method == "GET" {
			projects := []Project{}
			for _, v := range s.Store.Read().Tenants[p.Tenant].Projects {
				projects = append(projects, v)
			}
			slices.SortFunc(projects, func(a, b Project) int { return strings.Compare(a.ID, b.ID) })
			reply(w, 200, projects)
			return
		}
		if r.Method == "POST" && p.Can("write") {
			var v Project
			if decode(w, r, &v) != nil || !identity.ValidID(v.ID) || v.Name == "" || len(v.Name) > 256 || len(v.Owner) > 256 {
				reply(w, 400, nil)
				return
			}
			e := s.Store.UpdateAs(p, r.Method+" "+r.URL.Path, func(st *State) error {
				t := st.Tenants[p.Tenant]
				if _, ok := t.Projects[v.ID]; ok {
					return fmt.Errorf("project exists")
				}
				if len(t.Projects) >= 1000 {
					return fmt.Errorf("project quota reached")
				}
				t.Projects[v.ID] = v
				return nil
			})
			if e != nil {
				reply(w, 409, nil)
				return
			}
			reply(w, 201, v)
			return
		}
	}
	if r.URL.Path == "/api/v1/jobs" {
		if r.Method == "GET" {
			jobs := []Job{}
			for _, j := range s.Store.Read().Tenants[p.Tenant].Jobs {
				j.Report = nil
				j.Lease = ""
				jobs = append(jobs, j)
			}
			slices.SortFunc(jobs, func(a, b Job) int { return strings.Compare(a.ID, b.ID) })
			reply(w, 200, jobs)
			return
		}
		if r.Method == "POST" && p.Can("scan") {
			var req struct {
				ID      string `json:"id"`
				Project string `json:"project"`
			}
			if decode(w, r, &req) != nil || !identity.ValidID(req.ID) {
				reply(w, 400, nil)
				return
			}
			j := Job{ID: req.ID, Project: req.Project, Status: "queued", RequestedBy: p.Subject, Created: UTC()}
			e := s.Store.UpdateAs(p, r.Method+" "+r.URL.Path, func(st *State) error {
				t := st.Tenants[p.Tenant]
				if old, ok := t.Jobs[j.ID]; ok {
					if old.Project != j.Project || old.RequestedBy != p.Subject {
						return fmt.Errorf("idempotency conflict")
					}
					j = old
					return nil
				}
				if _, ok := t.Projects[j.Project]; !ok || len(t.Jobs) >= 10000 {
					return fmt.Errorf("invalid project or job quota reached")
				}
				t.Jobs[j.ID] = j
				return nil
			})
			if e != nil {
				reply(w, 409, nil)
				return
			}
			reply(w, 201, j)
			return
		}
	}
	if id := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/"); id != r.URL.Path && identity.ValidID(id) {
		j, ok := s.Store.Read().Tenants[p.Tenant].Jobs[id]
		if !ok {
			reply(w, 404, nil)
			return
		}
		if r.Method == "GET" {
			j.Lease = ""
			reply(w, 200, j)
			return
		}
		if r.Method == "DELETE" && p.Can("scan") {
			e := s.Store.UpdateAs(p, r.Method+" "+r.URL.Path, func(st *State) error {
				v := st.Tenants[p.Tenant].Jobs[id]
				v.Status = "cancelled"
				v.Lease = ""
				st.Tenants[p.Tenant].Jobs[id] = v
				return nil
			})
			if e != nil {
				reply(w, 503, nil)
				return
			}
			reply(w, 200, map[string]string{"status": "cancelled"})
			return
		}
	}
	reply(w, 404, nil)
}
