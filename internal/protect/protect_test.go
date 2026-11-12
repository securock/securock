package protect_test

import (
	"context"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/protect"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIndexContentAndAuthenticatedException(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); e != nil {
			t.Fatalf("%v %s", e, b)
		}
	}
	run("init", "-q")
	secret := "ghp_" + strings.Repeat("A", 36)
	path := filepath.Join(dir, "document.md")
	_ = os.WriteFile(path, []byte(secret), 0600)
	run("add", "document.md")
	_ = os.WriteFile(path, []byte("clean worktree; staged credential remains"), 0600)
	r, e := protect.Staged(context.Background(), dir)
	if e != nil || len(r.Findings) == 0 {
		t.Fatal(r, e)
	}
	if strings.Contains(r.Findings[0].Detail, secret) {
		t.Fatal("secret disclosed")
	}
	f := r.Findings[0]
	a := control.Approval{ID: "exception", Artifact: protect.Artifact(f), Rule: f.ID, Status: "approved", Requester: "developer", Reviewer: "security", Reason: "test-only", Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	accepted := protect.Apply(r, map[string]control.Approval{"exception": a}, time.Now())
	if accepted.Findings[0].Suppressed == nil {
		t.Fatal("valid exception rejected")
	}
	r.Findings[0].Suppressed = nil
	a.Reviewer = a.Requester
	if protect.Apply(r, map[string]control.Approval{"exception": a}, time.Now()).Findings[0].Suppressed != nil {
		t.Fatal("self-approved bypass")
	}
	if _, e = protect.Receive(context.Background(), dir, strings.NewReader(strings.Repeat("a", 65537))); e == nil {
		t.Fatal("truncated hook input accepted")
	}
}
