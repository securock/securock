package deno_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/deno"
	"github.com/securock/securock/internal/npmrc"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("npm_config_registry", "")
	t.Setenv("NPM_CONFIG_REGISTRY", "")
}

func TestDependencies(t *testing.T) {
	isolate(t)
	eco := deno.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected deno.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Ecosystem+":"+dep.Name] = dep
	}
	react := got["npm:react"]
	if react.Ecosystem != "npm" || react.Resolver != "deno" || react.Version != "19.2.0" {
		t.Fatalf("npm react = %+v", react)
	}
	if react.SourceKind != core.SourceRegistry {
		t.Fatalf("react kind = %q", react.SourceKind)
	}
	if react.Registry != "https://registry.npmjs.org" {
		t.Fatalf("react registry = %q", react.Registry)
	}
	std := got["jsr:@std/assert"]
	if std.Version != "1.0.6" || std.Registry != "https://jsr.io" {
		t.Fatalf("jsr = %+v", std)
	}
	remote := got["url:https://example.com/mod.ts"]
	if remote.SourceKind != core.SourceURL || remote.Version == "" {
		t.Fatalf("url = %+v", remote)
	}
	if remote.Digest != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("url digest = %q", remote.Digest)
	}
	signals := got["npm:@preact/signals"]
	if signals.Version != "1.3.2" {
		t.Fatalf("npm peer context version = %+v", signals)
	}
	redir := got["url:https://esm.sh/preact"]
	if redir.Requested != "https://esm.sh/preact" || redir.Resolved != "https://esm.sh/preact@10.26.8" {
		t.Fatalf("redirect = %+v", redir)
	}
	if redir.Digest != "sha256:f6c6195e67293b6df707b53dd3075ca149604e1ba989c7832179b3c1b7e8a302" {
		t.Fatalf("redirect digest = %q", redir.Digest)
	}
	if _, ok := got["url:https://esm.sh/preact@10.26.8"]; ok {
		t.Fatal("redirect target must not be a second url artifact")
	}
}

func TestV3Packages(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `{
  "version": "3",
  "packages": {
    "npm": {
      "chalk@5.3.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "chalk" || deps[0].Version != "5.3.0" {
		t.Fatalf("v3 npm = %#v", deps)
	}
}

func TestV4Lockfile(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `{
  "version": "4",
  "npm": {
    "chalk@5.3.0": { "integrity": "sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "chalk" || deps[0].Version != "5.3.0" {
		t.Fatalf("v4 npm = %#v", deps)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `{"version":"6","npm":{"react@19.2.0":{"integrity":"sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="}}}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := deno.New().Dependencies(dir)
	if err == nil || !strings.Contains(err.Error(), `unsupported deno.lock version "6"`) {
		t.Fatalf("want unsupported version error, got %v", err)
	}
}

func TestMissingVersion(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `{"npm":{"react@19.2.0":{"integrity":"sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="}}}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := deno.New().Dependencies(dir)
	if err == nil || !strings.Contains(err.Error(), "missing deno.lock version") {
		t.Fatalf("want missing version error, got %v", err)
	}
}

func TestNPMPeerContext(t *testing.T) {
	isolate(t)
	cases := []struct {
		key, name, version string
	}{
		{"@preact/signals@1.3.2_preact@10.26.8", "@preact/signals", "1.3.2"},
		{"preact@10.26.8", "preact", "10.26.8"},
		{"foo@1.0.0_@scope/bar@2.0.0", "foo", "1.0.0"},
		{"pkg@1.0.0_a@2.0.0_b@3.0.0", "pkg", "1.0.0"},
		{"react@19.2.0", "react", "19.2.0"},
		{"@octokit/plugin-rest-endpoint-methods@13.2.6_@octokit+core@6.1.2", "@octokit/plugin-rest-endpoint-methods", "13.2.6"},
		{"probot@13.4.0_@octokit+core@5.2.0_dotenv@16.4.5", "probot", "13.4.0"},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		raw := fmt.Sprintf(`{"version":"5","npm":{%q:{"integrity":"sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="}}}`, tc.key)
		if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		deps, err := deno.New().Dependencies(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(deps) != 1 || deps[0].Name != tc.name || deps[0].Version != tc.version {
			t.Fatalf("%s = %#v, want %s@%s", tc.key, deps, tc.name, tc.version)
		}
	}
}

func TestDefaultRegistryWithoutNpmrc(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "deno.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range deps {
		if dep.Ecosystem != "npm" {
			continue
		}
		if dep.Registry != npmrc.DefaultRegistry {
			t.Fatalf("%s registry = %q, want default npm", dep.Name, dep.Registry)
		}
	}
}

func TestPrivateProjectNpmrc(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(`{"version":"5","npm":{"react@19.2.0":{"integrity":"sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry=https://npm.company.example/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://npm.company.example" {
		t.Fatalf("project private npmrc = %#v", deps)
	}
}

func TestPrivateHomeNpmrc(t *testing.T) {
	isolate(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte("registry=https://npm.company.example/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(`{"version":"5","npm":{"react@19.2.0":{"integrity":"sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://npm.company.example" {
		t.Fatalf("home private npmrc = %#v", deps)
	}
}

func TestPrivateEnvRegistry(t *testing.T) {
	isolate(t)
	t.Setenv("NPM_CONFIG_REGISTRY", "https://npm.company.example/")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(`{"version":"5","npm":{"react@19.2.0":{"integrity":"sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://npm.company.example" {
		t.Fatalf("env private registry = %#v", deps)
	}
}

func TestRedirectWithoutRemoteHash(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `{
  "version": "5",
  "redirects": {
    "https://esm.sh/preact": "https://esm.sh/preact@10.26.8"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "deno.lock"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := deno.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %#v", deps)
	}
	dep := deps[0]
	if dep.Name != "https://esm.sh/preact" || dep.Resolved != "https://esm.sh/preact@10.26.8" {
		t.Fatalf("redirect = %+v", dep)
	}
	if dep.Version != "" {
		t.Fatalf("redirect without hash must omit version, got %q", dep.Version)
	}
}
