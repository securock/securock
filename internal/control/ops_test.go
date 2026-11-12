package control_test

import (
	"bytes"
	"github.com/securock/securock/internal/control"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupRestoreAndConsole(t *testing.T) {
	s, token, _ := fixture(t)
	request(s, token("alice"), "POST", "/api/v1/projects", `{"id":"repo","name":"private","owner":"team"}`)
	backup := filepath.Join(t.TempDir(), "backup.enc")
	if e := s.Store.Backup(backup); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(t.TempDir(), "restored")
	if e := control.Restore(backup, target, bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)); e != nil {
		t.Fatal(e)
	}
	r, e := control.Open(target, bytes.Repeat([]byte{7}, 32), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if r.Read().Tenants["a"].Projects["repo"].Name != "private" {
		t.Fatal("restore lost data")
	}
	wrong := filepath.Join(t.TempDir(), "wrong")
	if e := control.Restore(backup, wrong, bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 32)); e == nil {
		t.Fatal("wrong key accepted")
	}
	if _, e := os.Stat(wrong); !os.IsNotExist(e) {
		t.Fatal("failed restore retained files")
	}
	if request(s, token("dev"), "GET", "/api/v1/export", "").Code != 403 {
		t.Fatal("export permission")
	}
	w := request(s, "", "GET", "/ui", "")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "sha256-") || strings.Contains(w.Body.String(), "localStorage") {
		t.Fatal("unsafe console")
	}
}
