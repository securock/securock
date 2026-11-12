package control

import (
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/identity"
	"net/http"
	"slices"
	"strings"
	"time"
)

func (s *Server) runnerAPI(w http.ResponseWriter, r *http.Request, p identity.Principal) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/v1/runner/") {
		return false
	}
	if !p.Can("run") || r.Method != "POST" {
		reply(w, 403, nil)
		return true
	}
	var result Job
	e := error(nil)
	switch r.URL.Path {
	case "/api/v1/runner/claim":
		var req struct {
			Projects []string `json:"projects"`
		}
		if decode(w, r, &req) != nil || len(req.Projects) == 0 || len(req.Projects) > 1000 {
			reply(w, 400, nil)
			return true
		}
		e = s.Store.UpdateAs(p, "runner.claim", func(st *State) error {
			t := st.Tenants[p.Tenant]
			ids := []string{}
			for id := range t.Jobs {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			now := time.Now()
			for _, id := range ids {
				j := t.Jobs[id]
				until, _ := time.Parse(time.RFC3339, j.LeaseUntil)
				if j.Status == "running" && j.Runner == p.Subject && until.After(now) && slices.Contains(req.Projects, j.Project) {
					result = j
					return nil
				}
			}
			for _, id := range ids {
				j := t.Jobs[id]
				until, _ := time.Parse(time.RFC3339, j.LeaseUntil)
				if j.Status == "running" && !until.After(now) {
					if j.Attempts >= 3 {
						j.Status = "failed"
					} else {
						j.Status = "queued"
					}
					j.Lease = ""
					t.Jobs[id] = j
				}
				if j.Status != "queued" || !slices.Contains(req.Projects, j.Project) {
					continue
				}
				j.Status = "running"
				j.Runner = p.Subject
				j.Lease = ID()
				j.LeaseUntil = now.Add(5 * time.Minute).UTC().Format(time.RFC3339)
				j.Attempts++
				t.Jobs[id] = j
				result = j
				return nil
			}
			return nil
		})
	case "/api/v1/runner/complete":
		var req struct {
			ID     string          `json:"id"`
			Lease  string          `json:"lease"`
			Report *finding.Report `json:"report"`
			Failed bool            `json:"failed"`
		}
		if decode(w, r, &req) != nil {
			reply(w, 400, nil)
			return true
		}
		e = s.Store.UpdateAs(p, "runner.complete", func(st *State) error {
			t := st.Tenants[p.Tenant]
			j, ok := t.Jobs[req.ID]
			until, _ := time.Parse(time.RFC3339, j.LeaseUntil)
			if !ok || j.Status != "running" || j.Runner != p.Subject || req.Lease == "" || req.Lease != j.Lease || !until.After(time.Now()) {
				return fmt.Errorf("stale or cancelled lease")
			}
			if !req.Failed {
				if req.Report == nil || req.Report.Tool != "security" || req.Report.Findings == nil {
					return fmt.Errorf("report required")
				}
				for _, f := range req.Report.Findings {
					if f.ID == "" || f.Title == "" || f.Severity.Rank() < 0 {
						return fmt.Errorf("invalid finding")
					}
				}
				j.Report = req.Report
				j.Status = "completed"
			} else {
				j.Status = "failed"
			}
			j.Lease = ""
			t.Jobs[j.ID] = j
			result = j
			return nil
		})
	default:
		reply(w, 404, nil)
		return true
	}
	if e != nil {
		reply(w, 409, nil)
		return true
	}
	reply(w, 200, result)
	return true
}
