package pnpm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pnpm"
)

func load(t *testing.T, body string) map[string]core.Dependency {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := pnpm.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range deps {
		out[core.Identity(dep)] = dep
	}
	return out
}

func check(t *testing.T, deps map[string]core.Dependency, id, scope string, edges ...string) {
	t.Helper()
	dep, ok := deps[id]
	if !ok {
		t.Fatalf("%s not found", id)
	}
	if dep.Scope != scope {
		t.Errorf("%s scope = %q, want %q", id, dep.Scope, scope)
	}
	if len(dep.DependsOn) != len(edges) {
		t.Fatalf("%s depends on %v, want %v", id, dep.DependsOn, edges)
	}
	for i, want := range edges {
		if dep.DependsOn[i] != want {
			t.Errorf("%s depends on %v, want %v", id, dep.DependsOn, edges)
		}
	}
}

func TestV9ImportersAndSnapshots(t *testing.T) {
	deps := load(t, `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react:
        specifier: ^19.2.0
        version: 19.2.0
      lodash:
        specifier: ^4
        version: 4.17.21(react@19.2.0)
      '@scope/linked':
        specifier: workspace:*
        version: link:../linked
    devDependencies:
      jest:
        specifier: ^29
        version: 29.0.0
  packages/web:
    optionalDependencies:
      fsevents:
        specifier: '*'
        version: 2.3.0

packages:
  react@19.2.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
  lodash@4.17.21:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
  shared@1.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
  jest@29.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
  jest-util@29.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
  fsevents@2.3.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
  aliased@1.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}

snapshots:
  react@19.2.0: {}
  lodash@4.17.21(react@19.2.0):
    dependencies:
      shared: 1.0.0
      react: 19.2.0
      renamed: aliased@1.0.0
      absent: 9.9.9
  lodash@4.17.21(react@18.0.0):
    dependencies:
      shared: 1.0.0
  jest@29.0.0:
    dependencies:
      jest-util: 29.0.0
      shared: 1.0.0
  jest-util@29.0.0: {}
  shared@1.0.0: {}
  fsevents@2.3.0: {}
  aliased@1.0.0: {}
`)

	check(t, deps, "npm:react@19.2.0", core.ScopeRuntime)
	check(t, deps, "npm:lodash@4.17.21", core.ScopeRuntime, "npm:aliased@1.0.0", "npm:react@19.2.0", "npm:shared@1.0.0")
	// shared is a dev dependency of jest and a runtime dependency of lodash: runtime wins.
	check(t, deps, "npm:shared@1.0.0", core.ScopeRuntime)
	check(t, deps, "npm:aliased@1.0.0", core.ScopeRuntime)
	check(t, deps, "npm:jest@29.0.0", core.ScopeDev, "npm:jest-util@29.0.0", "npm:shared@1.0.0")
	check(t, deps, "npm:jest-util@29.0.0", core.ScopeDev)
	check(t, deps, "npm:fsevents@2.3.0", core.ScopeOptional)
}

func TestV6ProjectWithoutImporters(t *testing.T) {
	deps := load(t, `lockfileVersion: '6.0'

dependencies:
  app-lib:
    specifier: ^1
    version: 1.0.0

devDependencies:
  tester:
    specifier: ^1
    version: 1.0.0

packages:
  /app-lib@1.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
    dependencies:
      helper: 1.0.0
    dev: false
  /helper@1.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
    dev: false
  /tester@1.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
    dev: true
`)

	check(t, deps, "npm:app-lib@1.0.0", core.ScopeRuntime, "npm:helper@1.0.0")
	check(t, deps, "npm:helper@1.0.0", core.ScopeRuntime)
	check(t, deps, "npm:tester@1.0.0", core.ScopeDev)
}

func TestV5StyleScalarVersions(t *testing.T) {
	deps := load(t, `lockfileVersion: 5.4

dependencies:
  app-lib: 1.0.0

packages:
  /app-lib@1.0.0:
    resolution: {integrity: sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=}
`)
	check(t, deps, "npm:app-lib@1.0.0", core.ScopeRuntime)
}
