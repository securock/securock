package yarn_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/yarn"
)

func project(t *testing.T, files map[string]string) map[string]core.Dependency {
	t.Helper()
	isolate(t)
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	deps, err := yarn.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range deps {
		out[core.Identity(dep)] = dep
	}
	return out
}

func expect(t *testing.T, deps map[string]core.Dependency, id, scope string, edges ...string) {
	t.Helper()
	dep, ok := deps[id]
	if !ok {
		t.Fatalf("%s not found in %d deps", id, len(deps))
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

const pkgJSON = `{
  "name": "app",
  "dependencies": { "app-lib": "^1.0.0" },
  "devDependencies": { "tester": "^2.0.0" }
}`

func TestClassicScopeAndEdges(t *testing.T) {
	deps := project(t, map[string]string{
		"package.json": pkgJSON,
		"yarn.lock": `# yarn lockfile v1

app-lib@^1.0.0:
  version "1.2.0"
  resolved "https://registry.npmjs.org/app-lib/-/app-lib-1.2.0.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
  dependencies:
    shared "^1.0.0"
    "@scope/util" "^3.0.0"

tester@^2.0.0:
  version "2.1.0"
  resolved "https://registry.npmjs.org/tester/-/tester-2.1.0.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
  dependencies:
    shared "^1.0.0"
    tester-only "^1.0.0"

"shared@^1.0.0", shared@^1.1.0:
  version "1.3.0"
  resolved "https://registry.npmjs.org/shared/-/shared-1.3.0.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=

"@scope/util@^3.0.0":
  version "3.0.1"
  resolved "https://registry.npmjs.org/@scope/util/-/util-3.0.1.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=

tester-only@^1.0.0:
  version "1.0.0"
  resolved "https://registry.npmjs.org/tester-only/-/tester-only-1.0.0.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`,
	})

	expect(t, deps, "npm:app-lib@1.2.0", core.ScopeRuntime, "npm:@scope/util@3.0.1", "npm:shared@1.3.0")
	expect(t, deps, "npm:shared@1.3.0", core.ScopeRuntime)
	expect(t, deps, "npm:@scope/util@3.0.1", core.ScopeRuntime)
	expect(t, deps, "npm:tester@2.1.0", core.ScopeDev, "npm:shared@1.3.0", "npm:tester-only@1.0.0")
	expect(t, deps, "npm:tester-only@1.0.0", core.ScopeDev)
}

func TestBerryScopeAndEdges(t *testing.T) {
	deps := project(t, map[string]string{
		"package.json": `{
  "name": "app",
  "workspaces": ["packages/*"],
  "dependencies": { "app-lib": "^1.0.0" }
}`,
		"packages/web/package.json": `{ "name": "web", "devDependencies": { "tester": "^2.0.0" } }`,
		"yarn.lock": `__metadata:
  version: 8
  cacheKey: 10c0

"app-lib@npm:^1.0.0":
  version: 1.2.0
  resolution: "app-lib@npm:1.2.0"
  dependencies:
    shared: ^1.0.0
  checksum: 10c0/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  languageName: node
  linkType: hard

"tester@npm:^2.0.0":
  version: 2.1.0
  resolution: "tester@npm:2.1.0"
  dependencies:
    shared: ^1.0.0
    tester-only: ^1.0.0
  checksum: 10c0/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  languageName: node
  linkType: hard

"shared@npm:^1.0.0":
  version: 1.3.0
  resolution: "shared@npm:1.3.0"
  checksum: 10c0/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  languageName: node
  linkType: hard

"tester-only@npm:^1.0.0":
  version: 1.0.0
  resolution: "tester-only@npm:1.0.0"
  checksum: 10c0/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  languageName: node
  linkType: hard

"shared@npm:^1.0.0::locator=web%40workspace%3Apackages%2Fweb":
  version: 1.3.0
  resolution: "shared@npm:1.3.0"
  checksum: 10c0/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  languageName: node
  linkType: hard
`,
	})

	expect(t, deps, "npm:app-lib@1.2.0", core.ScopeRuntime, "npm:shared@1.3.0")
	expect(t, deps, "npm:shared@1.3.0", core.ScopeRuntime)
	expect(t, deps, "npm:tester@2.1.0", core.ScopeDev, "npm:shared@1.3.0", "npm:tester-only@1.0.0")
	expect(t, deps, "npm:tester-only@1.0.0", core.ScopeDev)
}

func TestWithoutPackageJSONScopesStayUnknown(t *testing.T) {
	deps := project(t, map[string]string{
		"yarn.lock": `# yarn lockfile v1

app-lib@^1.0.0:
  version "1.2.0"
  resolved "https://registry.npmjs.org/app-lib/-/app-lib-1.2.0.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
  dependencies:
    shared "^1.0.0"

shared@^1.0.0:
  version "1.3.0"
  resolved "https://registry.npmjs.org/shared/-/shared-1.3.0.tgz"
  integrity sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`,
	})
	// Edges are still known, but nothing says which packages the project asked for.
	expect(t, deps, "npm:app-lib@1.2.0", "", "npm:shared@1.3.0")
	expect(t, deps, "npm:shared@1.3.0", "")
}
