package control

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"net/http"
	"slices"
	"strings"
)

const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

type scimRole struct {
	Value string `json:"value"`
}
type scimUser struct {
	Schemas []string   `json:"schemas"`
	ID      string     `json:"id,omitempty"`
	Subject string     `json:"userName"`
	Active  bool       `json:"active"`
	Roles   []scimRole `json:"roles"`
}

func user(m Member) scimUser {
	roles := []scimRole{}
	for _, r := range m.Roles {
		roles = append(roles, scimRole{r})
	}
	return scimUser{[]string{userSchema}, m.ID, m.Subject, m.Active, roles}
}
func scimReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if v != nil {
		_ = jsonResponse(w, v)
	}
}
func scimError(w http.ResponseWriter, status int) {
	scimReply(w, status, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprint(status), "detail": "SCIM operation rejected"})
}
func (s *Server) scim(w http.ResponseWriter, r *http.Request, p identity.Principal) {
	if !p.Can("provision") {
		scimError(w, 403)
		return
	}
	base := "/scim/v2/Users"
	id := strings.TrimPrefix(r.URL.Path, base+"/")
	collection := r.URL.Path == base
	if !collection && !identity.ValidID(id) {
		scimError(w, 404)
		return
	}
	members := s.Store.Read().Tenants[p.Tenant].Members
	if r.Method == "GET" {
		if !collection {
			for _, m := range members {
				if m.ID == id {
					scimReply(w, 200, user(m))
					return
				}
			}
			scimError(w, 404)
			return
		}
		filter := r.URL.Query().Get("filter")
		resources := []scimUser{}
		for _, m := range members {
			if filter != "" && filter != `userName eq `+fmt.Sprintf("%q", m.Subject) {
				continue
			}
			resources = append(resources, user(m))
		}
		slices.SortFunc(resources, func(a, b scimUser) int { return strings.Compare(a.ID, b.ID) })
		scimReply(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources})
		return
	}
	var req scimUser
	var patch struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if r.Method == "POST" || r.Method == "PUT" {
		if decode(w, r, &req) != nil || !slices.Contains(req.Schemas, userSchema) || req.Subject == "" || len(req.Subject) > 256 {
			scimError(w, 400)
			return
		}
	} else if r.Method == "PATCH" {
		if decode(w, r, &patch) != nil || len(patch.Operations) == 0 || len(patch.Operations) > 10 {
			scimError(w, 400)
			return
		}
	}
	var result Member
	e := s.Store.UpdateAs(p, "scim."+r.Method, func(st *State) error {
		t := st.Tenants[p.Tenant]
		var old Member
		for _, m := range t.Members {
			if m.ID == id {
				old = m
			}
		}
		if !collection && (old.ID == "" || slices.Contains(old.Roles, "admin") || slices.Contains(old.Roles, "provisioner")) {
			return fmt.Errorf("protected or missing member")
		}
		switch r.Method {
		case "POST":
			if !collection || len(t.Members) >= 1000 {
				return fmt.Errorf("invalid create")
			}
			for _, tenant := range st.Tenants {
				if _, ok := tenant.Members[req.Subject]; ok {
					return fmt.Errorf("subject already bound")
				}
			}
			result = Member{ID: ID(), Subject: req.Subject, Active: req.Active}
			for _, v := range req.Roles {
				result.Roles = append(result.Roles, v.Value)
			}
		case "PUT":
			if collection || old.Subject != req.Subject {
				return fmt.Errorf("subject immutable")
			}
			result = Member{ID: old.ID, Subject: old.Subject, Active: req.Active}
			for _, v := range req.Roles {
				result.Roles = append(result.Roles, v.Value)
			}
		case "PATCH":
			result = old
			for _, op := range patch.Operations {
				if !strings.EqualFold(op.Op, "replace") {
					return fmt.Errorf("only replace patches supported")
				}
				switch strings.ToLower(op.Path) {
				case "active":
					if json.Unmarshal(op.Value, &result.Active) != nil {
						return fmt.Errorf("invalid active")
					}
				case "roles":
					var roles []scimRole
					if json.Unmarshal(op.Value, &roles) != nil {
						return fmt.Errorf("invalid roles")
					}
					result.Roles = nil
					for _, role := range roles {
						result.Roles = append(result.Roles, role.Value)
					}
				default:
					return fmt.Errorf("unsupported patch path")
				}
			}
		case "DELETE":
			if collection {
				return fmt.Errorf("invalid delete")
			}
			result = old
			result.Active = false
		default:
			return fmt.Errorf("unsupported method")
		}
		if len(result.Roles) == 0 {
			return fmt.Errorf("roles required")
		}
		for _, role := range result.Roles {
			if !slices.Contains([]string{"reader", "developer", "reviewer", "runner"}, role) {
				return fmt.Errorf("protected role")
			}
		}
		t.Members[result.Subject] = result
		return nil
	})
	if e != nil {
		scimError(w, 409)
		return
	}
	if r.Method == "DELETE" {
		scimReply(w, 204, nil)
		return
	}
	status := 200
	if r.Method == "POST" {
		status = 201
		w.Header().Set("Location", base+"/"+result.ID)
	}
	scimReply(w, status, user(result))
}
