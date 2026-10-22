package composer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/composer"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestScopeAndEdges(t *testing.T) {
	dir := t.TempDir()
	lock := `{
  "packages": [
    { "name": "Monolog/Monolog", "version": "3.0.0", "require": { "php": ">=8.1", "ext-json": "*", "psr/log": "^3" }, "dist": { "url": "https://example.com/m.zip" } },
    { "name": "psr/log", "version": "3.0.2", "dist": { "url": "https://example.com/l.zip" } }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "11.0.0", "require": { "psr/log": "^3", "sebastian/diff": "*" }, "dist": { "url": "https://example.com/p.zip" } },
    { "name": "sebastian/diff", "version": "5.0.0", "dist": { "url": "https://example.com/d.zip" } }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := composer.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	deps := map[string]core.Dependency{}
	for _, dep := range list {
		deps[dep.Name] = dep
	}

	want := map[string]string{
		"Monolog/Monolog": core.ScopeRuntime, "psr/log": core.ScopeRuntime,
		"phpunit/phpunit": core.ScopeDev, "sebastian/diff": core.ScopeDev,
	}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
	// php and ext-json are not packages; names match case-insensitively.
	if got := deps["Monolog/Monolog"].DependsOn; len(got) != 1 || got[0] != "packagist:psr/log@3.0.2" {
		t.Errorf("monolog edges = %v", got)
	}
	if got := deps["phpunit/phpunit"].DependsOn; len(got) != 2 {
		t.Errorf("phpunit edges = %v", got)
	}
}
