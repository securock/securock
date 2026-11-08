package workspace_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/securock/securock/internal/workspace"
)

func touch(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	touch(t, root,
		"package-lock.json",
		"services/web/package-lock.json",
		"services/api/go.mod",
		"services/api/internal/readme.md",
		// Not projects: dependencies, build output, fixtures, hidden directories.
		"services/web/node_modules/left-pad/package-lock.json",
		"services/api/vendor/x/go.mod",
		"dist/package-lock.json",
		"testdata/package-lock.json",
		".cache/package-lock.json",
	)
	got, err := workspace.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".", "services/api", "services/web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiscoverFindsNothingInAnEmptyTree(t *testing.T) {
	got, err := workspace.Discover(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestDiscoverRootThatIsHidden(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".work")
	touch(t, root, "package-lock.json")
	got, err := workspace.Discover(root)
	if err != nil || !reflect.DeepEqual(got, []string{"."}) {
		t.Fatalf("a root the user named must be searched: %v, %v", got, err)
	}
}

func TestDiscoverRejectsMissingAndFileRoots(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "file")
	for _, root := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "file")} {
		if _, err := workspace.Discover(root); err == nil {
			t.Errorf("%s should be rejected", root)
		}
	}
}
