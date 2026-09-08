package npm_test

import (
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/npm"
)

func TestDependencies(t *testing.T) {
	eco := npm.New()
	dir := testdata(t)
	if !eco.Detect(dir) {
		t.Fatal("expected npm lockfile to be detected")
	}

	deps, err := eco.Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep.Digest
	}

	want := map[string]string{
		"react@19.2.0":     "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"@scope/pkg@1.2.3": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"nested@0.1.0":     "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d deps, want %d: %#v", len(got), len(want), got)
	}
	for key, digest := range want {
		if got[key] != digest {
			t.Errorf("%s digest = %q, want %q", key, got[key], digest)
		}
	}
}

func testdata(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata")
}
