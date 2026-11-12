package control_test

import (
	"bytes"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/identity"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEncryptionKeyRotationPreservesSignedHistory(t *testing.T) {
	for _, backend := range []string{"snapshot", "database"} {
		t.Run(backend, func(t *testing.T) {
			old := bytes.Repeat([]byte{7}, 32)
			next := bytes.Repeat([]byte{8}, 32)
			seed := bytes.Repeat([]byte{9}, 32)
			dir := filepath.Join(t.TempDir(), "state")
			s, e := control.Open(dir, old, []identity.Binding{{Subject: "admin", Tenant: "a", Roles: []string{"admin"}}})
			if e != nil {
				t.Fatal(e)
			}
			if e = s.SetSigner(seed); e != nil {
				t.Fatal(e)
			}
			if backend == "database" {
				s.Close()
				dest := filepath.Join(t.TempDir(), "database")
				if e = control.MigrateDatabase(dir, dest, old, seed); e != nil {
					t.Fatal(e)
				}
				dir = dest
				s, e = control.Open(dir, old, nil)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.SetSigner(seed); e != nil {
					t.Fatal(e)
				}
			}
			before := s.Read()
			if e = s.Rekey([]byte("short")); e == nil {
				t.Fatal("short key accepted")
			}
			if e = s.Rekey(next); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, s.Read()) {
				t.Fatal("key rotation changed audit history")
			}
			s.Close()
			if bad, e := control.Open(dir, old, nil); e == nil {
				bad.Close()
				t.Fatal("old key still decrypts state")
			}
			restored, e := control.Open(dir, next, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer restored.Close()
			if e = restored.SetSigner(seed); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, restored.Read()) {
				t.Fatal("new key lost authenticated state")
			}
		})
	}
}
