package goenv_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/goenv"
)

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GOENV", "off")
	t.Setenv("GOPROXY", "")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
}

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultProxy(t *testing.T) {
	isolate(t)
	env := goenv.Load()
	if env.Proxy() != "https://proxy.golang.org" {
		t.Fatalf("default proxy = %q", env.Proxy())
	}
	if env.GOPRIVATE != "" || env.GONOPROXY != "" {
		t.Fatalf("default private = %+v", env)
	}
}

func TestUserFileWhenOSUnset(t *testing.T) {
	isolate(t)
	t.Setenv("GOENV", writeEnv(t, "GOPRIVATE=github.com/company/*\nGOPROXY=https://proxy.company.example,direct\n"))
	env := goenv.Load()
	if env.GOPRIVATE != "github.com/company/*" {
		t.Fatalf("GOPRIVATE = %q", env.GOPRIVATE)
	}
	if env.Proxy() != "https://proxy.company.example" {
		t.Fatalf("GOPROXY = %q", env.Proxy())
	}
	if !env.Private("github.com/company/secret") || !env.NoProxy("github.com/company/secret") {
		t.Fatal("go env -w GOPRIVATE must apply when OS is empty")
	}
	if env.Private("golang.org/x/mod") {
		t.Fatal("unrelated modules must stay public")
	}
}

func TestOSOverridesFile(t *testing.T) {
	isolate(t)
	t.Setenv("GOENV", writeEnv(t, "GOPRIVATE=from.file/*\n"))
	t.Setenv("GOPRIVATE", "from.os/*")
	env := goenv.Load()
	if env.GOPRIVATE != "from.os/*" {
		t.Fatalf("OS GOPRIVATE = %q", env.GOPRIVATE)
	}
}

func TestGoEnvOffIgnoresFile(t *testing.T) {
	isolate(t)
	t.Setenv("GOENV", writeEnv(t, "GOPRIVATE=github.com/company/*\n"))
	t.Setenv("GOENV", "off")
	env := goenv.Load()
	if env.GOPRIVATE != "" {
		t.Fatalf("GOENV=off must ignore the user file: %+v", env)
	}
}

func TestNoProxyDefaultsToPrivate(t *testing.T) {
	isolate(t)
	t.Setenv("GOPRIVATE", "*.corp.example.com")
	env := goenv.Load()
	if env.GONOPROXY != "*.corp.example.com" {
		t.Fatalf("GONOPROXY default = %q", env.GONOPROXY)
	}
	if !env.NoProxy("git.corp.example.com/xyzzy") {
		t.Fatal("unset GONOPROXY must follow GOPRIVATE")
	}
}

func TestNoProxyNoneOverridesPrivate(t *testing.T) {
	isolate(t)
	t.Setenv("GOPRIVATE", "*.corp.example.com")
	t.Setenv("GONOPROXY", "none")
	env := goenv.Load()
	if env.NoProxy("git.corp.example.com/xyzzy") {
		t.Fatal("GONOPROXY=none must allow the proxy")
	}
	if !env.Private("git.corp.example.com/xyzzy") {
		t.Fatal("GOPRIVATE still names the module as private")
	}
}

func TestNoProxyFromFileDefaultsPrivate(t *testing.T) {
	isolate(t)
	t.Setenv("GOENV", writeEnv(t, "GOPRIVATE=example.com/foo\nGONOPROXY=none\n"))
	env := goenv.Load()
	if env.NoProxy("example.com/foo") {
		t.Fatal("file GONOPROXY=none must override GOPRIVATE")
	}
}

func TestProxySingleWithDirect(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "https://proxy.company.example,direct")
	if got := goenv.Load().Proxy(); got != "https://proxy.company.example" {
		t.Fatalf("got %q", got)
	}
}

func TestProxyPipeDirect(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "https://proxy.golang.org|direct")
	if got := goenv.Load().Proxy(); got != "https://proxy.golang.org" {
		t.Fatalf("got %q", got)
	}
}

func TestProxyChainUnknown(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "https://proxy.golang.org,https://proxy.company.example")
	if got := goenv.Load().Proxy(); got != "" {
		t.Fatalf("ambiguous GOPROXY = %q", got)
	}
}

func TestProxyPipeChainUnknown(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "https://proxy.golang.org|https://goproxy.io,direct")
	if got := goenv.Load().Proxy(); got != "" {
		t.Fatalf("pipe GOPROXY = %q", got)
	}
}

func TestProxyDirect(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "direct")
	if got := goenv.Load().Proxy(); got != "" {
		t.Fatalf("direct = %q", got)
	}
}

func TestProxyImplicitHTTPS(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "proxy.company.example,direct")
	if got := goenv.Load().Proxy(); got != "https://proxy.company.example" {
		t.Fatalf("got %q", got)
	}
}

func TestProxyOffStopsList(t *testing.T) {
	isolate(t)
	t.Setenv("GOPROXY", "off,https://proxy.golang.org")
	if got := goenv.Load().Proxy(); got != "" {
		t.Fatalf("off must ignore later proxies: %q", got)
	}
}
