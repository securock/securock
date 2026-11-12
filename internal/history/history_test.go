package history_test

import (
	"context"
	"github.com/securock/securock/internal/history"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeletedCredentialAndBudgets(t *testing.T) {
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "no-global-config"))
	dir := t.TempDir()
	git := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if raw, e := c.CombinedOutput(); e != nil {
			t.Fatalf("%v %s", e, raw)
		}
	}
	git("init", "-q", "--template="+t.TempDir())
	git("config", "user.name", "Test")
	git("config", "user.email", "test@example.test")
	token := "AKIA" + "1234567890ABCDEF"
	p := filepath.Join(dir, "notes.txt")
	os.WriteFile(p, []byte("access="+token+"\n"), 0600)
	git("add", "notes.txt")
	git("commit", "-qm", "add credential fixture")
	os.Remove(p)
	git("add", "-u")
	git("commit", "-qm", "remove credential fixture")
	r, e := history.Scan(context.Background(), history.Options{Path: dir, Revision: "HEAD", MaxCommits: 10, MaxBlobs: 10})
	if e != nil || len(r.Findings) != 1 || r.Findings[0].ID != "history:secrets/aws-access-key" || strings.Contains(r.Findings[0].Detail, token) {
		t.Fatal(r, e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("working tree restored historical secret")
	}
	if _, e := history.Scan(context.Background(), history.Options{Path: dir, Revision: "HEAD", MaxCommits: 1, MaxBlobs: 10}); e == nil {
		t.Fatal("truncated history passed as complete")
	}
	git("config", "remote.origin.promisor", "true")
	if _, e := history.Scan(context.Background(), history.Options{Path: dir, Revision: "HEAD", MaxCommits: 10, MaxBlobs: 10}); e == nil {
		t.Fatal("partial clone accepted without complete content")
	}
	git("config", "--unset", "remote.origin.promisor")
	head, e := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, ".git", "shallow"), head, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := history.Scan(context.Background(), history.Options{Path: dir, Revision: "HEAD", MaxCommits: 10, MaxBlobs: 10}); e == nil {
		t.Fatal("shallow history passed as complete")
	}

}
