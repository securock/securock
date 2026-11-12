package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Backup authenticates state and audit history before exporting encrypted bytes.
func (s *Store) Backup(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.signer) == 0 {
		return fmt.Errorf("audit signer required")
	}
	public := s.signer.Public().(ed25519.PublicKey)
	for _, t := range s.state.Tenants {
		if e := VerifyAudit(AuditExport{1, base64.StdEncoding.EncodeToString(public), t.Audit}, public); e != nil {
			return e
		}
	}
	raw, e := os.ReadFile(filepath.Join(s.dir, "state.enc"))
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(raw); e != nil {
		return e
	}
	return f.Sync()
}
func Restore(path, dir string, key, seed []byte) error {
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		return fmt.Errorf("restore requires an absent destination directory")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65<<20+1))
	f.Close()
	if e != nil || len(raw) > 65<<20 {
		return fmt.Errorf("backup exceeds limit")
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(dir)
		}
	}()
	if e = os.WriteFile(filepath.Join(dir, "state.enc"), raw, 0600); e != nil {
		return e
	}
	s, e := Open(dir, key, nil)
	if e != nil {
		return e
	}
	defer s.Close()
	if e = s.SetSigner(seed); e != nil {
		return e
	}
	success = true
	return nil
}
func (s *Store) Manifest() ([]byte, error) {
	v := s.Read()
	counts := map[string]int{}
	for id, t := range v.Tenants {
		counts[id] = len(t.Jobs)
	}
	return json.Marshal(map[string]any{"version": 1, "tenants": counts})
}
