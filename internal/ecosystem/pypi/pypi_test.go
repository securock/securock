package pypi_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pypi"
)

func TestDependencies(t *testing.T) {
	eco := pypi.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected uv lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deps, want 3: %#v", len(deps), deps)
	}

	got := map[string]string{}
	files := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version+"#"+dep.Filename] = dep.Digest
		files[dep.Filename] = dep.Name
	}
	if got["requests@2.32.3#requests-2.32.3.tar.gz"] != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("requests digest = %#v", got)
	}
	if _, ok := files["idna-3.10-py3-none-any.whl"]; !ok {
		t.Fatalf("missing any wheel: %#v", files)
	}
	if _, ok := files["idna-3.10-cp312-cp312-macosx_11_0_arm64.whl"]; !ok {
		t.Fatalf("missing macos wheel: %#v", files)
	}
}

func TestGitSource(t *testing.T) {
	dir := t.TempDir()
	raw := `version = 1

[[package]]
name = "git-pkg"
version = "1.0.0"
source = { git = "https://github.com/example/git-pkg#abc123" }
`
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pypi.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1: %#v", len(deps), deps)
	}
	if deps[0].SourceKind != core.SourceGit || deps[0].Registry != "" {
		t.Fatalf("git source = %+v", deps[0])
	}
}

func TestPathSource(t *testing.T) {
	dir := t.TempDir()
	raw := `version = 1

[[package]]
name = "local-pkg"
version = "0.0.1"
source = { directory = "../local-pkg" }
`
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pypi.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1: %#v", len(deps), deps)
	}
	if deps[0].SourceKind != core.SourceFile || deps[0].Registry != "" {
		t.Fatalf("path source = %+v", deps[0])
	}
}

func TestDefaultRegistry(t *testing.T) {
	dir := t.TempDir()
	raw := `version = 1

[[package]]
name = "requests"
version = "2.32.3"
sdist = { url = "https://files.pythonhosted.org/packages/requests-2.32.3.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }
`
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pypi.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1: %#v", len(deps), deps)
	}
	if deps[0].Registry != "https://pypi.org" || deps[0].SourceKind != core.SourceRegistry {
		t.Fatalf("default registry = %+v", deps[0])
	}
}
