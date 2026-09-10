package golang_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/golang"
)

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GOPROXY", "")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
}

func TestDependencies(t *testing.T) {
	isolate(t)
	eco := golang.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected go lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2: %#v", len(deps), deps)
	}

	got := map[string]core.Dependency{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep
		if dep.SourceKind != core.SourceRegistry || dep.Registry != "https://proxy.golang.org" {
			t.Fatalf("source = %+v", dep)
		}
	}
	cobra := got["github.com/spf13/cobra@v1.9.1"]
	if cobra.Digest != "goh1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" {
		t.Fatalf("cobra digest = %q", cobra.Digest)
	}
	if _, ok := got["golang.org/x/sys@v0.0.0-20220811171246-acb485596380"]; !ok {
		t.Fatalf("missing sys: %#v", got)
	}
}

func TestIgnoresGoSumLeftovers(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	mod := `module example.com/app

go 1.22

require github.com/spf13/cobra v1.9.1
`
	sum := `github.com/spf13/cobra v1.9.1 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
example.com/unused v1.0.0 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`
	writeGo(t, dir, mod, sum)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "github.com/spf13/cobra" {
		t.Fatalf("leftover go.sum entries must be ignored: %#v", deps)
	}
}

func TestReplaceLocal(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	mod := `module example.com/app

go 1.22

require example.com/foo v1.2.3

replace example.com/foo => ../foo
`
	sum := `example.com/foo v1.2.3 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`
	writeGo(t, dir, mod, sum)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	dep := deps[0]
	if dep.Name != "example.com/foo" || dep.Version != "v1.2.3" {
		t.Fatalf("dep = %+v", dep)
	}
	if dep.SourceKind != core.SourceFile || dep.Registry != "" || dep.Digest != "" {
		t.Fatalf("local replace must not keep the module sum: %+v", dep)
	}
	if dep.Artifact != "" {
		t.Fatalf("local replace must omit the path: %+v", dep)
	}
}

func TestReplaceRemote(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	mod := `module example.com/app

go 1.22

require example.com/foo v1.2.3

replace example.com/foo => example.com/bar v1.3.0
`
	sum := `example.com/foo v1.2.3 h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
example.com/bar v1.3.0 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`
	writeGo(t, dir, mod, sum)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	dep := deps[0]
	if dep.Name != "example.com/foo" || dep.Version != "v1.3.0" {
		t.Fatalf("dep = %+v", dep)
	}
	if dep.Artifact != "example.com/bar" || dep.Resolved != "v1.3.0" {
		t.Fatalf("replace source = %+v", dep)
	}
	if dep.Digest != "goh1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" {
		t.Fatalf("digest = %q", dep.Digest)
	}
	if dep.Requested != "example.com/foo@v1.2.3" {
		t.Fatalf("requested = %q", dep.Requested)
	}
	if dep.Registry != "https://proxy.golang.org" {
		t.Fatalf("public replace must use GOPROXY: %+v", dep)
	}
}

func TestGoProxyDirect(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "direct")
	dir := t.TempDir()
	writeGo(t, dir, `module example.com/app

go 1.22

require github.com/spf13/cobra v1.9.1
`, `github.com/spf13/cobra v1.9.1 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("GOPROXY=direct must not record a proxy: %#v", deps)
	}
}

func TestReplaceRemotePublicForkDespitePrivateRequire(t *testing.T) {
	isolate(t)
	t.Setenv("GOPRIVATE", "example.com/foo")
	dir := t.TempDir()
	writeGo(t, dir, `module example.com/app

go 1.22

require example.com/foo v1.2.3

replace example.com/foo => github.com/public/foo v1.3.0
`, `github.com/public/foo v1.3.0 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	dep := deps[0]
	if dep.Name != "example.com/foo" || dep.Artifact != "github.com/public/foo" {
		t.Fatalf("dep = %+v", dep)
	}
	if dep.Registry != "https://proxy.golang.org" {
		t.Fatalf("public fork must still use GOPROXY: %+v", dep)
	}
}

func TestGoProxyCompany(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "https://proxy.company.example,direct")
	dir := t.TempDir()
	writeGo(t, dir, `module example.com/app

go 1.22

require github.com/spf13/cobra v1.9.1
`, `github.com/spf13/cobra v1.9.1 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://proxy.company.example" {
		t.Fatalf("company GOPROXY = %#v", deps)
	}
}

func TestGoNoProxy(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "https://proxy.golang.org,direct")
	t.Setenv("GONOPROXY", "example.com/foo")
	dir := t.TempDir()
	writeGo(t, dir, `module example.com/app

go 1.22

require example.com/foo v1.2.3
`, `example.com/foo v1.2.3 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("GONOPROXY module must not use GOPROXY: %#v", deps)
	}
}

func TestReplaceRemotePrivateFork(t *testing.T) {
	isolate(t)
	t.Setenv("GOPRIVATE", "example.com/fork/*")
	dir := t.TempDir()
	writeGo(t, dir, `module example.com/app

go 1.22

require example.com/foo v1.2.3

replace example.com/foo => example.com/fork/foo v1.3.0
`, `example.com/bar v1.3.0 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
example.com/fork/foo v1.3.0 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=
`)
	deps, err := golang.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %#v", deps)
	}
	dep := deps[0]
	if dep.Name != "example.com/foo" || dep.Artifact != "example.com/fork/foo" {
		t.Fatalf("dep = %+v", dep)
	}
	if dep.Registry != "" {
		t.Fatalf("private fork must not use the public proxy: %+v", dep)
	}
}

func TestMissingGoMod(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("github.com/spf13/cobra v1.9.1 h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := golang.New().Dependencies(dir); err == nil {
		t.Fatal("go.sum without go.mod must fail")
	}
}

func writeGo(t *testing.T, dir, mod, sum string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(sum), 0o644); err != nil {
		t.Fatal(err)
	}
}
