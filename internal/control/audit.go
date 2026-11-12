package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"net/http"
	"strings"
	"time"
)

type AuditEvent struct {
	Sequence    int    `json:"sequence"`
	Actor       string `json:"actor"`
	Action      string `json:"action"`
	Time        string `json:"time"`
	Previous    string `json:"previous"`
	StateDigest string `json:"state_digest"`
	Signature   string `json:"signature"`
}
type AuditExport struct {
	Version   int          `json:"version"`
	PublicKey string       `json:"public_key"`
	Events    []AuditEvent `json:"events"`
}
type Approval struct {
	ID        string `json:"id"`
	Artifact  string `json:"artifact"`
	Rule      string `json:"rule"`
	Reason    string `json:"reason"`
	Expires   string `json:"expires"`
	Requester string `json:"requester"`
	Reviewer  string `json:"reviewer,omitempty"`
	Status    string `json:"status"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func (s *Store) SetSigner(seed []byte) error {
	if len(seed) != 32 {
		return fmt.Errorf("audit signing seed must be 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ed25519.NewKeyFromSeed(seed)
	for _, t := range s.state.Tenants {
		if e := VerifyAudit(AuditExport{Version: 1, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Events: t.Audit}, key.Public().(ed25519.PublicKey)); e != nil {
			return fmt.Errorf("audit signer does not match existing history")
		}
	}
	s.signer = key
	return nil
}
func VerifyAudit(v AuditExport, pinned ed25519.PublicKey) error {
	if v.Version != 1 || len(pinned) != 32 || v.PublicKey != base64.StdEncoding.EncodeToString(pinned) {
		return fmt.Errorf("audit trust anchor mismatch")
	}
	prev := ""
	for i, event := range v.Events {
		sig, e := base64.StdEncoding.DecodeString(event.Signature)
		unsigned := event
		unsigned.Signature = ""
		raw, _ := json.Marshal(unsigned)
		if e != nil || event.Sequence != i+1 || event.Previous != prev || !ed25519.Verify(pinned, raw, sig) {
			return fmt.Errorf("audit chain verification failed")
		}
		prev = digest(event)
	}
	return nil
}
func (s *Store) UpdateAs(p identity.Principal, action string, fn func(*State) error) error {
	return s.Update(func(st *State) error {
		if len(s.signer) != ed25519.PrivateKeySize {
			return fmt.Errorf("audit signer unavailable")
		}
		before := digest(st.Tenants[p.Tenant])
		if e := fn(st); e != nil {
			return e
		}
		t := st.Tenants[p.Tenant]
		if before == digest(t) {
			return nil
		}
		if t == nil {
			return fmt.Errorf("tenant missing")
		}
		copy := *t
		copy.Audit = nil
		event := AuditEvent{Sequence: len(t.Audit) + 1, Actor: p.Subject, Action: action, Time: UTC(), StateDigest: digest(copy)}
		if len(t.Audit) > 0 {
			event.Previous = digest(t.Audit[len(t.Audit)-1])
		}
		raw, _ := json.Marshal(event)
		event.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.signer, raw))
		t.Audit = append(t.Audit, event)
		return nil
	})
}
func (s *Server) auditAPI(w http.ResponseWriter, r *http.Request, p identity.Principal) bool {
	if r.URL.Path == "/api/v1/audit" && r.Method == "GET" {
		if !p.Can("read") {
			reply(w, 403, nil)
			return true
		}
		s.Store.mu.Lock()
		var public string
		if len(s.Store.signer) > 0 {
			public = base64.StdEncoding.EncodeToString(s.Store.signer.Public().(ed25519.PublicKey))
		}
		s.Store.mu.Unlock()
		reply(w, 200, AuditExport{1, public, s.Store.Read().Tenants[p.Tenant].Audit})
		return true
	}
	base := "/api/v1/approvals"
	if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
		return false
	}
	if r.Method == "GET" && p.Can("read") {
		items := map[string]Approval{}
		for id, a := range s.Store.Read().Tenants[p.Tenant].Approvals {
			exp, e := time.Parse(time.RFC3339, a.Expires)
			if e != nil || !exp.After(time.Now()) {
				a.Status = "expired"
			}
			items[id] = a
		}
		reply(w, 200, items)
		return true
	}
	var req struct {
		ID       string `json:"id"`
		Artifact string `json:"artifact"`
		Rule     string `json:"rule"`
		Reason   string `json:"reason"`
		Expires  string `json:"expires"`
		Status   string `json:"status"`
	}
	if decode(w, r, &req) != nil {
		reply(w, 400, nil)
		return true
	}
	var result Approval
	e := s.Store.UpdateAs(p, "approval."+r.Method, func(st *State) error {
		t := st.Tenants[p.Tenant]
		if t.Approvals == nil {
			t.Approvals = map[string]Approval{}
		}
		if r.Method == "POST" && r.URL.Path == base && p.Can("write") {
			raw, e := hex.DecodeString(req.Artifact)
			exp, te := time.Parse(time.RFC3339, req.Expires)
			if !identity.ValidID(req.ID) || e != nil || len(raw) != 32 || req.Rule == "" || req.Reason == "" || len(req.Reason) > 2048 || te != nil || !exp.After(time.Now()) || exp.After(time.Now().Add(30*24*time.Hour)) {
				return fmt.Errorf("invalid approval scope or expiry")
			}
			if _, ok := t.Approvals[req.ID]; ok {
				return fmt.Errorf("approval exists")
			}
			result = Approval{ID: req.ID, Artifact: req.Artifact, Rule: req.Rule, Reason: req.Reason, Expires: req.Expires, Requester: p.Subject, Status: "pending"}
			t.Approvals[result.ID] = result
			return nil
		}
		id := strings.TrimPrefix(r.URL.Path, base+"/")
		old, ok := t.Approvals[id]
		exp, _ := time.Parse(time.RFC3339, old.Expires)
		if r.Method != "PUT" || !p.Can("approve") || !ok || old.Status != "pending" || old.Requester == p.Subject || !exp.After(time.Now()) || req.Status != "approved" && req.Status != "rejected" {
			return fmt.Errorf("approval rejected")
		}
		old.Status = req.Status
		old.Reviewer = p.Subject
		t.Approvals[id] = old
		result = old
		return nil
	})
	if e != nil {
		reply(w, 409, nil)
		return true
	}
	reply(w, 200, result)
	return true
}
