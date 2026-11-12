package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

type Connector struct {
	CloseTransition string `json:"close_transition,omitempty"`
	OpenTransition  string `json:"open_transition,omitempty"`
	ID              string `json:"id"`
	Tenant          string `json:"tenant"`
	Provider        string `json:"provider"`
	Origin          string `json:"origin"`
	Project         string `json:"project"`
	TokenEnv        string `json:"token_env"`
}
type Delivery struct {
	DesiredState string `json:"desired_state,omitempty"`
	ID           string `json:"id"`
	Connector    string `json:"connector"`
	Kind         string `json:"kind"`
	Title        string `json:"title"`
	Body         string `json:"body"`
	Commit       string `json:"commit,omitempty"`
	Branch       string `json:"branch,omitempty"`
	Base         string `json:"base,omitempty"`
	Result       string `json:"result,omitempty"`
	RemoteID     string `json:"remote_id,omitempty"`
	RemoteState  string `json:"remote_state,omitempty"`
	Status       string `json:"status"`
	Attempts     int    `json:"attempts"`
	Next         string `json:"next,omitempty"`
}

func ValidateConnectors(cs []Connector) error {
	seen := map[string]bool{}
	for _, c := range cs {
		u, e := url.Parse(c.Origin)
		if !identity.ValidID(c.ID) || !identity.ValidID(c.Tenant) || seen[c.Tenant+"/"+c.ID] || !slices.Contains([]string{"github", "gitlab", "jira", "servicenow"}, c.Provider) || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || c.TokenEnv == "" || c.Project == "" {
			return fmt.Errorf("invalid connector")
		}
		seen[c.Tenant+"/"+c.ID] = true
	}
	return nil
}
func (s *Server) connector(tenant, id string) (Connector, bool) {
	for _, c := range s.Connectors {
		if c.Tenant == tenant && c.ID == id {
			return c, true
		}
	}
	return Connector{}, false
}
func (s *Server) deliveryAPI(w http.ResponseWriter, r *http.Request, p identity.Principal) bool {
	if strings.HasPrefix(r.URL.Path, "/api/v1/deliveries/") && r.Method == "PUT" {
		if !p.Can("integration") {
			reply(w, 403, nil)
			return true
		}
		var req struct {
			State string `json:"state"`
		}
		if decode(w, r, &req) != nil || (req.State != "closed" && req.State != "open") {
			reply(w, 400, nil)
			return true
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/deliveries/")
		err := s.Store.UpdateAs(p, "delivery.update", func(st *State) error {
			d, ok := st.Tenants[p.Tenant].Deliveries[id]
			if !ok || d.Kind != "issue" || d.Status != "delivered" || d.RemoteID == "" {
				return fmt.Errorf("issue not delivered")
			}
			conn, ok := s.connector(p.Tenant, d.Connector)
			if !ok {
				return fmt.Errorf("connector missing")
			}
			if conn.Provider == "jira" && ((req.State == "closed" && conn.CloseTransition == "") || (req.State == "open" && conn.OpenTransition == "")) {
				return fmt.Errorf("jira transition mapping required")
			}
			d.DesiredState = req.State
			d.Status = "queued"
			d.Next = ""
			d.Attempts = 0
			st.Tenants[p.Tenant].Deliveries[id] = d
			return nil
		})
		if err != nil {
			reply(w, 409, nil)
		} else {
			reply(w, 200, map[string]string{"status": "queued"})
		}
		return true
	}
	if r.URL.Path != "/api/v1/deliveries" {
		return false
	}
	if !p.Can("integration") {
		reply(w, 403, nil)
		return true
	}
	if r.Method == "GET" {
		reply(w, 200, s.Store.Read().Tenants[p.Tenant].Deliveries)
		return true
	}
	var req Delivery
	if r.Method != "POST" || decode(w, r, &req) != nil || !identity.ValidID(req.ID) || !slices.Contains([]string{"issue", "pull", "check"}, req.Kind) || req.Title == "" || len(req.Title) > 256 || len(req.Body) > 20000 || req.RemoteID != "" || req.Status != "" || req.Attempts != 0 || req.Next != "" || req.RemoteState != "" || req.DesiredState != "" {
		reply(w, 400, nil)
		return true
	}
	conn, ok := s.connector(p.Tenant, req.Connector)
	if !ok || req.Kind != "issue" && conn.Provider != "github" && conn.Provider != "gitlab" || req.Kind == "pull" && (req.Branch == "" || req.Base == "") || req.Kind == "check" && (len(req.Commit) != 40 && len(req.Commit) != 64 || req.Result != "success" && req.Result != "failure") {
		reply(w, 400, nil)
		return true
	}
	req.Status = "queued"
	e := s.Store.UpdateAs(p, "delivery.queue", func(st *State) error {
		t := st.Tenants[p.Tenant]
		if t.Deliveries == nil {
			t.Deliveries = map[string]Delivery{}
		}
		if old, ok := t.Deliveries[req.ID]; ok {
			if old.Connector == req.Connector && old.Kind == req.Kind && old.Title == req.Title && old.Body == req.Body && old.Commit == req.Commit && old.Branch == req.Branch && old.Base == req.Base && old.Result == req.Result {
				req = old
				return nil
			}
			return fmt.Errorf("idempotency conflict")
		}
		if len(t.Deliveries) >= 10000 {
			return fmt.Errorf("outbox quota")
		}
		t.Deliveries[req.ID] = req
		return nil
	})
	if e != nil {
		reply(w, 409, nil)
		return true
	}
	reply(w, 201, req)
	return true
}
func remotePath(c Connector, d Delivery, poll bool) (string, any, error) {
	project := url.PathEscape(c.Project)
	id := url.PathEscape(d.RemoteID)
	if poll {
		switch c.Provider {
		case "github":
			return "/repos/" + strings.ReplaceAll(project, "%2F", "/") + "/issues/" + id, nil, nil
		case "gitlab":
			return "/projects/" + project + "/issues/" + id, nil, nil
		case "jira":
			return "/rest/api/3/issue/" + id, nil, nil
		case "servicenow":
			return "/api/now/table/incident/" + id, nil, nil
		}
	}
	switch c.Provider {
	case "github":
		prefix := "/repos/" + strings.ReplaceAll(project, "%2F", "/")
		switch d.Kind {
		case "pull":
			return prefix + "/pulls", map[string]any{"title": d.Title, "body": d.Body, "head": d.Branch, "base": d.Base}, nil
		case "check":
			return prefix + "/check-runs", map[string]any{"name": d.Title, "head_sha": d.Commit, "status": "completed", "conclusion": d.Result, "output": map[string]string{"title": d.Title, "summary": d.Body}}, nil
		default:
			return prefix + "/issues", map[string]string{"title": d.Title, "body": d.Body}, nil
		}
	case "gitlab":
		prefix := "/projects/" + project
		switch d.Kind {
		case "pull":
			return prefix + "/merge_requests", map[string]string{"title": d.Title, "description": d.Body, "source_branch": d.Branch, "target_branch": d.Base}, nil
		case "check":
			state := "success"
			if d.Result == "failure" {
				state = "failed"
			}
			return prefix + "/statuses/" + url.PathEscape(d.Commit), map[string]string{"state": state, "name": d.Title, "description": d.Body}, nil
		default:
			return prefix + "/issues", map[string]string{"title": d.Title, "description": d.Body}, nil
		}
	case "jira":
		return "/rest/api/3/issue", map[string]any{"fields": map[string]any{"project": map[string]string{"key": c.Project}, "summary": d.Title, "issuetype": map[string]string{"name": "Task"}, "description": map[string]any{"type": "doc", "version": 1, "content": []any{map[string]any{"type": "paragraph", "content": []any{map[string]string{"type": "text", "text": d.Body}}}}}}}, nil
	case "servicenow":
		return "/api/now/table/incident", map[string]string{"short_description": d.Title, "description": d.Body, "correlation_id": "securock-" + d.ID}, nil
	}
	return "", nil, fmt.Errorf("unsupported provider")
}

// Dispatch makes at most one bounded call. Ambiguous creates are never blindly replayed.
func (s *Server) Dispatch(ctx context.Context) error {
	state := s.Store.Read()
	tenants := []string{}
	for id := range state.Tenants {
		tenants = append(tenants, id)
	}
	slices.Sort(tenants)
	for _, tenant := range tenants {
		t := state.Tenants[tenant]
		ids := []string{}
		for id := range t.Deliveries {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			d := t.Deliveries[id]
			poll := d.Status == "delivered" && d.Kind == "issue"
			next, _ := time.Parse(time.RFC3339, d.Next)
			if d.Status != "queued" && !poll || next.After(time.Now()) {
				continue
			}
			c, ok := s.connector(tenant, d.Connector)
			if !ok {
				continue
			}
			p := identity.Principal{Subject: "connector:" + c.ID, Tenant: tenant, Roles: []string{"integration"}}
			if !poll {
				if e := s.Store.UpdateAs(p, "delivery.start", func(st *State) error {
					v := st.Tenants[tenant].Deliveries[id]
					if v.Status != "queued" {
						return fmt.Errorf("already claimed")
					}
					v.Status = "sending"
					v.Attempts++
					st.Tenants[tenant].Deliveries[id] = v
					d = v
					return nil
				}); e != nil {
					return e
				}
			}
			path, payload, e := remotePath(c, d, poll)
			if e != nil {
				return e
			}
			raw, _ := json.Marshal(payload)
			method := "POST"
			update := !poll && d.RemoteID != "" && d.DesiredState != ""
			if update {
				path, _, e = remotePath(c, d, true)
				if e != nil {
					return e
				}
				switch c.Provider {
				case "github":
					method = "PATCH"
					payload = map[string]string{"state": d.DesiredState}
				case "gitlab":
					method = "PUT"
					event := "close"
					if d.DesiredState == "open" {
						event = "reopen"
					}
					payload = map[string]string{"state_event": event}
				case "servicenow":
					method = "PATCH"
					state := "6"
					if d.DesiredState == "open" {
						state = "1"
					}
					payload = map[string]string{"state": state}
				case "jira":
					method = "POST"
					path += "/transitions"
					transition := c.CloseTransition
					if d.DesiredState == "open" {
						transition = c.OpenTransition
					}
					payload = map[string]any{"transition": map[string]string{"id": transition}}
				}
				raw, _ = json.Marshal(payload)
			}
			if poll {
				method = "GET"
			}
			req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Origin, "/")+path, bytes.NewReader(raw))
			if e != nil {
				return fmt.Errorf("invalid connector request")
			}
			token := os.Getenv(c.TokenEnv)
			if token == "" || strings.ContainsAny(token, "\r\n") {
				return fmt.Errorf("connector token unavailable; reconcile sending record before retry")
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Idempotency-Key", "securock-"+d.ID)
			if c.Provider == "gitlab" {
				req.Header.Set("PRIVATE-TOKEN", token)
			}
			h := &http.Client{Timeout: 20 * time.Second}
			if s.DeliveryClient != nil {
				*h = *s.DeliveryClient
			}
			h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			resp, callErr := h.Do(req)
			status := 0
			var data map[string]any
			if resp != nil {
				status = resp.StatusCode
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				if readErr != nil {
					callErr = readErr
				}
				if json.Unmarshal(body, &data) != nil && status >= 200 && status < 300 && status != 204 {
					callErr = fmt.Errorf("invalid provider response")
				}
			}
			e = s.Store.UpdateAs(p, "delivery.result", func(st *State) error {
				v := st.Tenants[tenant].Deliveries[id]
				v.Next = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
				if callErr != nil || status < 200 || status >= 300 {
					if !poll {
						v.Status = "uncertain"
						if status == 429 && v.Attempts < 3 {
							v.Status = "queued"
						}
						if status >= 400 && status < 500 && status != 429 {
							v.Status = "failed"
						}
					}
				} else {
					if !poll {
						v.Status = "delivered"
					}
					switch c.Provider {
					case "github":
						if !poll && !update {
							v.RemoteID = fmt.Sprint(data["number"])
						}
						v.RemoteState = fmt.Sprint(data["state"])
					case "gitlab":
						if !poll && !update {
							v.RemoteID = fmt.Sprint(data["iid"])
						}
						v.RemoteState = fmt.Sprint(data["state"])
					case "jira":
						if !poll && !update {
							v.RemoteID = fmt.Sprint(data["key"])
						}
						if fields, ok := data["fields"].(map[string]any); ok {
							if status, ok := fields["status"].(map[string]any); ok {
								v.RemoteState = fmt.Sprint(status["name"])
							}
						}
					case "servicenow":
						if result, ok := data["result"].(map[string]any); ok {
							if !poll {
								v.RemoteID = fmt.Sprint(result["sys_id"])
							}
							v.RemoteState = fmt.Sprint(result["state"])
						}
					}
					if v.Kind == "issue" && (v.RemoteID == "" || v.RemoteID == "<nil>") {
						v.Status = "uncertain"
					}
				}
				st.Tenants[tenant].Deliveries[id] = v
				return nil
			})
			return e
		}
	}
	return nil
}
