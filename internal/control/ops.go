package control

import (
	"fmt"
	"github.com/securock/securock/internal/identity"
	"net/http"
	"time"
)

func (s *Server) opsAPI(w http.ResponseWriter, r *http.Request, p identity.Principal) bool {
	switch r.URL.Path {
	case "/api/v1/metrics":
		if !p.Can("read") || r.Method != "GET" {
			reply(w, 403, nil)
			return true
		}
		t := s.Store.Read().Tenants[p.Tenant]
		statuses := map[string]int{}
		severity := map[string]int{}
		for _, j := range t.Jobs {
			statuses[j.Status]++
			if j.Report != nil {
				for _, f := range j.Report.Findings {
					if f.Suppressed == nil {
						severity[string(f.Severity)]++
					}
				}
			}
		}
		reply(w, 200, map[string]any{"projects": len(t.Projects), "jobs": statuses, "findings": severity})
		return true
	case "/api/v1/export":
		if !p.Can("admin") || r.Method != "GET" {
			reply(w, 403, nil)
			return true
		}
		t := s.Store.Read().Tenants[p.Tenant]
		for id, j := range t.Jobs {
			j.Lease = ""
			t.Jobs[id] = j
		}
		reply(w, 200, t)
		return true
	case "/api/v1/retention":
		if !p.Can("admin") || r.Method != "POST" {
			reply(w, 403, nil)
			return true
		}
		var req struct {
			Before string `json:"before"`
		}
		if decode(w, r, &req) != nil {
			reply(w, 400, nil)
			return true
		}
		cutoff, e := time.Parse(time.RFC3339, req.Before)
		if e != nil || cutoff.After(time.Now()) {
			reply(w, 400, nil)
			return true
		}
		deleted := 0
		e = s.Store.UpdateAs(p, "retention.purge", func(st *State) error {
			t := st.Tenants[p.Tenant]
			for id, j := range t.Jobs {
				created, e := time.Parse(time.RFC3339, j.Created)
				if e != nil {
					return fmt.Errorf("invalid job creation time")
				}
				if created.Before(cutoff) && j.Status != "queued" && j.Status != "running" {
					delete(t.Jobs, id)
					deleted++
				}
			}
			return nil
		})
		if e != nil {
			reply(w, 503, nil)
		} else {
			reply(w, 200, map[string]int{"deleted_jobs": deleted})
		}
		return true
	}
	return false
}
