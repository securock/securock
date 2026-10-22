package pub_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pub"
)

func TestScopeFromDependencyKind(t *testing.T) {
	dir := t.TempDir()
	entry := func(name, kind string) string {
		return "  " + name + ":\n    dependency: \"" + kind + "\"\n    description:\n      name: " + name +
			"\n      sha256: \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n      url: \"https://pub.dev\"\n    source: hosted\n    version: \"1.0.0\"\n"
	}
	lock := "packages:\n" + entry("main_pkg", "direct main") + entry("dev_pkg", "direct dev") +
		entry("over_pkg", "direct overridden") + entry("trans_pkg", "transitive") + "sdks:\n  dart: \">=3.0.0 <4.0.0\"\n"
	if err := os.WriteFile(filepath.Join(dir, "pubspec.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := pub.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"main_pkg": core.ScopeRuntime, "dev_pkg": core.ScopeDev, "over_pkg": core.ScopeRuntime,
		// pub does not say whether a transitive package serves main or dev dependencies.
		"trans_pkg": "",
	}
	for _, dep := range list {
		if dep.Scope != want[dep.Name] {
			t.Errorf("%s = %q, want %q", dep.Name, dep.Scope, want[dep.Name])
		}
	}
	if len(list) != len(want) {
		t.Fatalf("got %d packages", len(list))
	}
}
