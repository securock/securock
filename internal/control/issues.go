package control

import (
	"fmt"
	"github.com/securock/securock/internal/identity"
	"github.com/securock/securock/internal/lifecycle"
	"net/http"
	"strings"
	"time"
)

func (s *Server) issueAPI(w http.ResponseWriter, r *http.Request, p identity.Principal) bool {
	if r.URL.Path == "/api/v1/connectors" && r.Method == "GET" {
		if !p.Can("read") {
			reply(w, 403, nil)
			return true
		}
		out := []map[string]string{}
		for _, c := range s.Connectors {
			if c.Tenant == p.Tenant {
				out = append(out, map[string]string{"id": c.ID, "provider": c.Provider, "project": c.Project})
			}
		}
		reply(w, 200, out)
		return true
	}
	base := "/api/v1/issues"
	if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
		return false
	}
	if r.Method == "GET" && p.Can("read") {
		asof := r.URL.Query().Get("as_of")
		if asof == "" {
			asof = time.Now().UTC().Format("2006-01-02")
		}
		out := map[string]lifecycle.Registry{}
		for project, registry := range s.Store.Tenant(p.Tenant).Registries {
			if e := lifecycle.Age(&registry, asof); e != nil {
				reply(w, 400, nil)
				return true
			}
			out[project] = registry
		}
		reply(w, 200, out)
		return true
	}
	if r.Method != "PUT" || !p.Can("write") {
		reply(w, 403, nil)
		return true
	}
	project := strings.TrimPrefix(r.URL.Path, base+"/")
	var req struct {
		Key   string `json:"key"`
		Owner string `json:"owner"`
		Due   string `json:"due"`
	}
	if decode(w, r, &req) != nil || len(req.Owner) > 256 {
		reply(w, 400, nil)
		return true
	}
	e := s.Store.UpdateAs(p, "issue.assign", func(st *State) error {
		t := st.Tenants[p.Tenant]
		registry, ok := t.Registries[project]
		if !ok {
			return fmt.Errorf("project work queue missing")
		}
		if e := lifecycle.Assign(&registry, req.Key, req.Owner, req.Due); e != nil {
			return e
		}
		t.Registries[project] = registry
		return nil
	})
	if e != nil {
		reply(w, 409, nil)
		return true
	}
	reply(w, 200, map[string]string{"status": "assigned"})
	return true
}
