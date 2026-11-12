package control_test

import (
	"bytes"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/identity"
	"path/filepath"
	"testing"
)

func TestEncryptionKeyAloneCannotForgeSignedState(t *testing.T) {
	s, _, dir := fixture(t)
	if e := s.Store.Update(func(st *control.State) error {
		m := st.Tenants["a"].Members["dev"]
		m.Roles = []string{"admin"}
		st.Tenants["a"].Members["dev"] = m
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.Store.Backup(filepath.Join(t.TempDir(), "forged.enc")); e == nil {
		t.Fatal("unaudited state backed up")
	}
	_ = s.Store.Close()
	restored, e := control.Open(dir, bytes.Repeat([]byte{7}, 32), []identity.Binding{{Subject: "injected", Tenant: "a", Roles: []string{"admin"}}})
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	if e = restored.SetSigner(bytes.Repeat([]byte{9}, 32)); e == nil {
		t.Fatal("altered snapshot authenticated by unchanged event chain")
	}
	if _, ok := restored.Read().Tenants["a"].Members["injected"]; ok {
		t.Fatal("startup configuration silently provisioned a new admin")
	}
}
