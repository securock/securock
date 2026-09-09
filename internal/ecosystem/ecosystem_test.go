package ecosystem_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestPreferPnpmOverNpm(t *testing.T) {
	found := []ecosystem.Ecosystem{
		fakeEco("pnpm"),
		fakeEco("npm"),
		fakeEco("go"),
	}
	got := ecosystem.Prefer(found)
	if len(got) != 2 {
		t.Fatalf("got %d ecosystems, want 2", len(got))
	}
	if got[0].Name() != "pnpm" || got[1].Name() != "go" {
		t.Fatalf("unexpected order: %v", names(got))
	}
}

func TestPreferYarnOverNpm(t *testing.T) {
	found := []ecosystem.Ecosystem{
		fakeEco("npm"),
		fakeEco("yarn"),
		fakeEco("go"),
	}
	got := ecosystem.Prefer(found)
	if len(got) != 2 {
		t.Fatalf("got %d ecosystems, want 2", len(got))
	}
	if got[0].Name() != "yarn" || got[1].Name() != "go" {
		t.Fatalf("unexpected order: %v", names(got))
	}
}

func TestPreferBunOverNpm(t *testing.T) {
	found := []ecosystem.Ecosystem{
		fakeEco("npm"),
		fakeEco("bun"),
		fakeEco("go"),
	}
	got := ecosystem.Prefer(found)
	if len(got) != 2 {
		t.Fatalf("got %d ecosystems, want 2", len(got))
	}
	if got[0].Name() != "bun" || got[1].Name() != "go" {
		t.Fatalf("unexpected order: %v", names(got))
	}
}

func TestCollectArtifactConflict(t *testing.T) {
	dir := t.TempDir()
	raw := `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/foo": {
      "version": "1.0.0",
      "integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    },
    "node_modules/nested/node_modules/foo": {
      "version": "1.0.0",
      "integrity": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ecosystem.Collect(dir)
	if err == nil || !strings.Contains(err.Error(), "artifact conflict") {
		t.Fatalf("expected conflict, got %v", err)
	}
}

type fakeEco string

func (f fakeEco) Name() string       { return string(f) }
func (fakeEco) OSVEcosystem() string { return "" }
func (fakeEco) Detect(string) bool   { return true }
func (fakeEco) Dependencies(string) ([]core.Dependency, error) {
	return nil, nil
}

func names(ecos []ecosystem.Ecosystem) []string {
	out := make([]string, 0, len(ecos))
	for _, e := range ecos {
		out = append(out, e.Name())
	}
	return out
}
