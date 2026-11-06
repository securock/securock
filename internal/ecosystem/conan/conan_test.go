package conan_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/securock/securock/internal/ecosystem/conan"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestDependencies(t *testing.T) {
	eco := conan.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected conan.lock to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	got := map[string]core.Dependency{}
	for _, dep := range deps {
		order = append(order, dep.Name)
		got[dep.Name] = dep
		if dep.Ecosystem != "conan" || dep.Resolver != "conan" {
			t.Fatalf("%s ecosystem/resolver = %s/%s", dep.Name, dep.Ecosystem, dep.Resolver)
		}
		if dep.Digest != "" || dep.Registry != "" {
			t.Fatalf("%s digest/registry = %q/%q, the lockfile proves neither", dep.Name, dep.Digest, dep.Registry)
		}
	}
	want := []string{"cmake", "mylib", "mytools", "norevision", "openssl", "zlib"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v (versionless and config_requires are skipped, zlib is deduplicated)", order, want)
	}

	tests := []struct {
		name, version, scope, revision string
	}{
		// In requires and build_requires: runtime wins.
		{"zlib", "1.3.1", core.ScopeRuntime, "f52e03ae3d251dec704634230cd806a2"},
		{"openssl", "3.2.1", core.ScopeRuntime, "0123456789abcdef0123456789abcdef"},
		{"mylib", "2.0", core.ScopeRuntime, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"norevision", "1.0", core.ScopeRuntime, ""},
		{"cmake", "3.28.1", core.ScopeDev, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{"mytools", "1.0", core.ScopeDev, "cccccccccccccccccccccccccccccccc"},
	}
	for _, tt := range tests {
		dep := got[tt.name]
		if dep.Version != tt.version || dep.Scope != tt.scope || dep.Resolved != tt.revision {
			t.Errorf("%s = %+v", tt.name, dep)
		}
	}
}

func TestRejectsUnsupportedAndMalformed(t *testing.T) {
	dir := t.TempDir()
	if _, err := conan.New().Dependencies(dir); err == nil {
		t.Fatal("expected an error for a missing lockfile")
	}
	for name, body := range map[string]string{
		"conan 1":   `{"graph_lock":{"nodes":{}},"version":"0.4"}`,
		"malformed": `{`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "conan.lock"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := conan.New().Dependencies(dir); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
