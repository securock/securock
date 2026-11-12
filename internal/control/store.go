// Package control provides a single-instance, encrypted security control plane.
package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/identity"
	"github.com/securock/securock/internal/lifecycle"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Member struct {
	ID      string   `json:"id"`
	Subject string   `json:"userName"`
	Active  bool     `json:"active"`
	Roles   []string `json:"roles"`
}
type Project struct {
	SLADays map[string]int `json:"sla_days,omitempty"`
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Owner   string         `json:"owner"`
}
type Job struct {
	LeaseUntil  string          `json:"lease_until,omitempty"`
	ID          string          `json:"id"`
	Project     string          `json:"project"`
	Status      string          `json:"status"`
	RequestedBy string          `json:"requested_by"`
	Created     string          `json:"created"`
	Report      *finding.Report `json:"report,omitempty"`
	Runner      string          `json:"runner,omitempty"`
	Lease       string          `json:"lease,omitempty"`
	Attempts    int             `json:"attempts"`
}
type Tenant struct {
	Registries map[string]lifecycle.Registry `json:"registries,omitempty"`
	Deliveries map[string]Delivery           `json:"deliveries,omitempty"`
	Approvals  map[string]Approval           `json:"approvals,omitempty"`
	Audit      []AuditEvent                  `json:"audit,omitempty"`
	Members    map[string]Member             `json:"members"`
	Projects   map[string]Project            `json:"projects"`
	Jobs       map[string]Job                `json:"jobs"`
}
type State struct {
	Version int                `json:"version"`
	Tenants map[string]*Tenant `json:"tenants"`
}
type Store struct {
	newState bool
	signer   ed25519.PrivateKey
	mu       sync.Mutex
	dir      string
	aead     cipher.AEAD
	state    State
}

func ID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func Open(dir string, key []byte, bindings []identity.Binding) (*Store, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("state encryption requires a 32-byte key")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("state directory must be a real directory")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	if e = os.Mkdir(filepath.Join(dir, "instance.lock"), 0700); e != nil {
		return nil, fmt.Errorf("state directory already locked; recover a stale lock only after confirming the previous process stopped")
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	s := &Store{dir: dir, aead: aead, state: State{Version: 1, Tenants: map[string]*Tenant{}}}
	if info, err := os.Stat(filepath.Join(dir, "state.enc")); err == nil && info.Size() > 65<<20 {
		s.Close()
		return nil, fmt.Errorf("encrypted state exceeds limit")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "state.enc"))
	s.newState = os.IsNotExist(e)
	if e == nil {
		if len(raw) < aead.NonceSize() {
			s.Close()
			return nil, fmt.Errorf("invalid encrypted state")
		}
		plain, e := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("securock-control-v1"))
		if e != nil || json.Unmarshal(plain, &s.state) != nil || s.state.Version != 1 || s.state.Tenants == nil {
			s.Close()
			return nil, fmt.Errorf("state authentication or version check failed")
		}
	} else if !os.IsNotExist(e) {
		s.Close()
		return nil, e
	}
	if s.newState {
		for _, b := range bindings {
			t := s.state.Tenants[b.Tenant]
			if t == nil {
				t = &Tenant{Members: map[string]Member{}, Projects: map[string]Project{}, Jobs: map[string]Job{}}
				s.state.Tenants[b.Tenant] = t
			}
			if _, ok := t.Members[b.Subject]; !ok {
				t.Members[b.Subject] = Member{ID: ID(), Subject: b.Subject, Active: true, Roles: b.Roles}
			}
		}
	}
	if e = validateState(s.state); e != nil {
		s.Close()
		return nil, e
	}
	if e = s.save(s.state); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return os.Remove(filepath.Join(s.dir, "instance.lock")) }
func (s *Store) save(v State) error {
	plain, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(plain) > 64<<20 {
		return fmt.Errorf("state capacity exceeded")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw := s.aead.Seal(nonce, nonce, plain, []byte("securock-control-v1"))
	f, e := os.CreateTemp(s.dir, "state-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(s.dir, "state.enc"))
}
func (s *Store) Read() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.state)
	var v State
	_ = json.Unmarshal(raw, &v)
	return v
}
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.state)
	var next State
	_ = json.Unmarshal(raw, &next)
	if e := fn(&next); e != nil {
		return e
	}
	if e := s.save(next); e != nil {
		return e
	}
	s.state = next
	return nil
}
func UTC() string { return time.Now().UTC().Format(time.RFC3339) }
