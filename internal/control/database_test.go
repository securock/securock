package control_test

import (
	"bytes"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/identity"
)

func TestDatabaseMigrationIsolationEncryptionAndRecovery(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	seed := bytes.Repeat([]byte{9}, 32)
	source := filepath.Join(t.TempDir(), "source")
	original, e := control.Open(source, key, []identity.Binding{{Subject: "alice", Tenant: "a", Roles: []string{"admin"}}, {Subject: "bob", Tenant: "b", Roles: []string{"admin"}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = original.SetSigner(seed); e != nil {
		t.Fatal(e)
	}
	if e = original.Close(); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(t.TempDir(), "database")
	if e = control.MigrateDatabase(source, dest, key, seed); e != nil {
		t.Fatal(e)
	}
	s, e := control.Open(dest, key, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SetSigner(seed); e != nil {
		t.Fatal(e)
	}
	p := identity.Principal{Subject: "alice", Tenant: "a", Roles: []string{"admin"}}
	projectID := control.ID()
	if e = s.UpdateAs(p, "project.create", func(st *control.State) error {
		st.Tenants["a"].Projects[projectID] = control.Project{ID: projectID, Name: "private-project-marker"}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	view := s.Tenant("a")
	view.Projects[projectID] = control.Project{}
	if s.Tenant("a").Projects[projectID].Name != "private-project-marker" {
		t.Fatal("tenant view aliases state")
	}
	if len(s.Tenant("b").Projects) != 0 {
		t.Fatal("cross-tenant data mutation")
	}
	if e = s.UpdateAs(p, "invalid.subject", func(st *control.State) error {
		st.Tenants["a"].Members["bob"] = control.Member{ID: control.ID(), Subject: "bob", Active: true, Roles: []string{"viewer"}}
		return nil
	}); e == nil {
		t.Fatal("cross-tenant duplicate subject accepted")
	}
	backup := filepath.Join(t.TempDir(), "backup.enc")
	if e = s.Backup(backup); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(backup)
	if bytes.Contains(raw, []byte("private-project-marker")) || bytes.Contains(raw, []byte("alice")) {
		t.Fatal("database leaked plaintext")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if e = control.RestoreDatabase(backup, restored, key, seed); e != nil {
		t.Fatal(e)
	}
	r, e := control.Open(restored, key, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = r.SetSigner(seed); e != nil {
		t.Fatal(e)
	}
	if r.Tenant("a").Projects[projectID].Name != "private-project-marker" {
		t.Fatal("restore lost state")
	}
	bad := filepath.Join(t.TempDir(), "bad")
	if e = control.RestoreDatabase(backup, bad, bytes.Repeat([]byte{1}, 32), seed); e == nil {
		t.Fatal("wrong restore key accepted")
	}
	if _, e = os.Stat(bad); !os.IsNotExist(e) {
		t.Fatal("failed restore destination retained")
	}
	// Disk access without the encryption key must not permit silent tenant deletion.
	db, e := bolt.Open(filepath.Join(dest, "state.db"), 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("securock-tenants-v1"))
		cursor := bucket.Cursor()
		for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
			if string(k) != "manifest" {
				return cursor.Delete()
			}
		}
		return fmt.Errorf("no tenant record")
	}); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if opened, e := control.Open(dest, key, nil); e == nil {
		opened.Close()
		t.Fatal("unauthenticated tenant deletion accepted")
	}

}

func BenchmarkTenantSnapshot(b *testing.B) {
	for _, count := range []int{1, 16} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			key := bytes.Repeat([]byte{7}, 32)
			bindings := []identity.Binding{}
			for i := 0; i < count; i++ {
				bindings = append(bindings, identity.Binding{Subject: fmt.Sprint("member", i), Tenant: fmt.Sprint("tenant", i), Roles: []string{"admin"}})
			}
			s, e := control.Open(filepath.Join(b.TempDir(), "state"), key, bindings)
			if e != nil {
				b.Fatal(e)
			}
			defer s.Close()
			if e = s.Update(func(st *control.State) error {
				for _, t := range st.Tenants {
					for i := 0; i < 1000; i++ {
						id := control.ID()
						t.Projects[id] = control.Project{ID: id, Name: strings.Repeat("x", 128)}
					}
				}
				return nil
			}); e != nil {
				b.Fatal(e)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.Tenant("tenant0")
			}
		})
	}
}
