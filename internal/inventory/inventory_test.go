package inventory_test

import (
	"context"
	"encoding/json"
	"github.com/securock/securock/internal/inventory"
	"github.com/securock/securock/schemas"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestObservedRuntimeAndDeclaredSource(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q", dir}, {"-C", dir, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "-q", "--allow-empty", "-m", "fixture"}} {
		if raw, e := exec.Command("git", args...).CombinedOutput(); e != nil {
			t.Fatalf("%v %s", e, raw)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("* @platform\n"), 0600)
	pods := []byte(`{"kind":"PodList","items":[{"metadata":{"name":"api","namespace":"prod","annotations":{"securock.dev/project":"."}},"spec":{"serviceAccountName":"api","containers":[{"name":"api","image":"untrusted:latest"},{"name":"sidecar","image":"tag-only"}]},"status":{"phase":"Running","containerStatuses":[{"name":"api","imageID":"docker-pullable://registry/api@sha256:` + strings.Repeat("a", 64) + `","state":{"running":{}}}]}}]}`)
	r, e := inventory.Discover(context.Background(), dir, pods)
	if e != nil {
		t.Fatal(e)
	}
	observed, declared := false, false
	for _, edge := range r.Edges {
		if edge.Relation == "runs" && edge.Evidence == "observed" {
			observed = true
		}
		if edge.Relation == "declared-source" && edge.Evidence == "declared" {
			declared = true
		}
	}
	if !observed || !declared || !strings.Contains(strings.Join(r.Gaps, "\n"), "sidecar") {
		t.Fatal(r)
	}
	raw, _ := json.Marshal(r)
	if e := schemas.Validate("inventory-report.schema.json", raw); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), dir) {
		t.Fatal("absolute path disclosed")
	}
}
