package mix_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/mix"
)

func TestDependencies(t *testing.T) {
	isolateHex(t)
	eco := mix.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected mix.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name] = dep
		if dep.Ecosystem != "hex" || dep.Resolver != "mix" {
			t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
		}
	}
	jason := got["jason"]
	if jason.Version != "1.4.4" {
		t.Fatalf("jason = %+v", jason)
	}
	if jason.SourceKind != core.SourceRegistry || jason.Registry != "https://repo.hex.pm" {
		t.Fatalf("jason source = %+v", jason)
	}
	if jason.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("jason digest = %q", jason.Digest)
	}
	if got["local_pkg"].SourceKind != core.SourceFile {
		t.Fatalf("local_pkg kind = %q", got["local_pkg"].SourceKind)
	}
}

func TestGitSource(t *testing.T) {
	dir := t.TempDir()
	raw := `%{
  "foo": {:git, "https://github.com/example/foo.git", "0123456789abcdef0123456789abcdef01234567", []},
}
`
	if err := os.WriteFile(filepath.Join(dir, "mix.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := mix.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	dep := deps[0]
	if dep.SourceKind != core.SourceGit || dep.Registry != "" {
		t.Fatalf("git = %+v", dep)
	}
	if dep.Artifact != "https://github.com/example/foo.git" {
		t.Fatalf("artifact = %q", dep.Artifact)
	}
	if dep.Resolved != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("resolved = %q", dep.Resolved)
	}
	if dep.Version != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("version = %q", dep.Version)
	}
}

func TestPrivateHexRepo(t *testing.T) {
	dir := t.TempDir()
	raw := `%{
  "secret": {:hex, :secret, "1.0.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "acme", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
}
`
	if err := os.WriteFile(filepath.Join(dir, "mix.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := mix.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("hex org repo must not assume hex.pm: %#v", deps)
	}
}

func hexLock(t *testing.T, body string) []core.Dependency {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mix.lock"), []byte("%{\n"+body+"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := mix.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func isolateHex(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("HEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, env := range []string{"HEX_MIRROR", "HEX_REPO_URL", "HEX_API_URL"} {
		t.Setenv(env, "")
	}
}

func TestLockWithoutRepoUnknown(t *testing.T) {
	isolateHex(t)
	// Older lock layout: no repo element. The nested requirement's repo must not count.
	deps := hexLock(t, `  "foo": {:hex, :foo, "1.0.0", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", [:mix], [{:bar, "~> 1.0", [hex: :bar, repo: "hexpm", optional: false]}]},`)
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("missing repo must be unknown: %#v", deps)
	}
}

func TestHexMirrorUnknown(t *testing.T) {
	isolateHex(t)
	t.Setenv("HEX_MIRROR", "https://hex-mirror.company.example")
	deps := hexLock(t, `  "jason": {:hex, :jason, "1.4.4", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},`)
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("mirrored hex must be unknown: %#v", deps)
	}
}

func TestHexConfigMirrorUnknown(t *testing.T) {
	isolateHex(t)
	home := os.Getenv("HOME")
	if err := os.MkdirAll(filepath.Join(home, ".hex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".hex", "hex.config"), []byte(`{mirror_url, <<"https://hex-mirror.company.example">>}.`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := hexLock(t, `  "jason": {:hex, :jason, "1.4.4", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},`)
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("hex.config mirror must be unknown: %#v", deps)
	}
}
