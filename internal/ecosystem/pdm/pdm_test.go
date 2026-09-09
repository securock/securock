package pdm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pdm"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
	t.Setenv("LOCALAPPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(home, "xdg"))
	t.Setenv("ProgramData", filepath.Join(home, "ProgramData"))
	t.Setenv("PDM_PYPI_URL", "")
}

func TestDependencies(t *testing.T) {
	isolate(t)
	eco := pdm.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected pdm.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "pypi" || dep.Resolver != "pdm" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	req := got["requests"]
	if req.Version != "2.32.3" || req.Filename != "requests-2.32.3.tar.gz" {
		t.Fatalf("requests = %+v", req)
	}
	if req.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("requests digest = %q", req.Digest)
	}
	if req.SourceKind != core.SourceRegistry || req.Registry != "https://pypi.org" {
		t.Fatalf("default pdm registry = %+v", req)
	}
	if got["local-pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local-pkg kind = %q", got["local-pkg"].SourceKind)
	}
}

func TestFileURLProvenance(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `[[package]]
name = "requests"
version = "2.32.3"
files = [
    {file = "requests-2.32.3.tar.gz", url = "https://pypi.org/packages/requests-2.32.3.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if err := os.WriteFile(filepath.Join(dir, "pdm.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pdm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://pypi.org" {
		t.Fatalf("pypi file url = %#v", deps)
	}
}

func TestPrivateIndexUnknown(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `[[package]]
name = "secret-sdk"
version = "1.0.0"
files = [
    {file = "secret-sdk-1.0.0.tar.gz", url = "https://pypi.company.example/packages/secret-sdk-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if err := os.WriteFile(filepath.Join(dir, "pdm.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pdm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://pypi.company.example" {
		t.Fatalf("private pdm = %#v", deps)
	}
}

func TestPyprojectExtraSourceUnknown(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	lock := `[[package]]
name = "requests"
version = "2.32.3"
files = [
    {file = "requests-2.32.3.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if err := os.WriteFile(filepath.Join(dir, "pdm.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	pyproject := `[[tool.pdm.source]]
name = "internal"
url = "https://pypi.company.example/simple"
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pdm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("pypi plus private source must be unknown: %#v", deps)
	}
}

func TestPyprojectReplacesDefaultIndex(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	lock := `[[package]]
name = "secret-sdk"
version = "1.0.0"
files = [
    {file = "secret-sdk-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if err := os.WriteFile(filepath.Join(dir, "pdm.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	pyproject := `[[tool.pdm.source]]
name = "pypi"
url = "https://pypi.company.example/simple"
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pdm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://pypi.company.example" {
		t.Fatalf("replaced pypi index = %#v", deps)
	}
}

func TestParentPyprojectSourceUnknown(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	project := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `[[package]]
name = "secret-sdk"
version = "1.0.0"
files = [
    {file = "secret-sdk-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if err := os.WriteFile(filepath.Join(project, "pdm.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	pyproject := `[[tool.pdm.source]]
name = "internal"
url = "https://pypi.company.example/simple"
`
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pdm.New().Dependencies(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("parent private source must not look public: %#v", deps)
	}
}

func TestUserConfigPrivateIndex(t *testing.T) {
	isolate(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(home, ".config", "pdm")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("pypi.url = \"https://pypi.company.example/simple\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lock := `[[package]]
name = "secret-sdk"
version = "1.0.0"
files = [
    {file = "secret-sdk-1.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
]
`
	if err := os.WriteFile(filepath.Join(dir, "pdm.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pdm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://pypi.company.example" {
		t.Fatalf("user pdm config = %#v", deps)
	}
}
