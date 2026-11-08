package cli_test

import (
	"strings"
	"testing"
)

func TestCacheClear(t *testing.T) {
	isolateHome(t)
	if out := string(runCLI(t, "cache", "clear")); !strings.Contains(out, "removed 0 cached responses") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestCacheFlags(t *testing.T) {
	isolateHome(t)
	dir := initProject(t)
	runCLI(t, "scan", dir, "--offline", "--no-fail", "--no-cache", "--cache-ttl", "10m")
	if _, err := runCLIErr(t, "scan", dir, "--offline", "--no-fail", "--cache-ttl", "-5m"); err == nil {
		t.Fatal("a negative --cache-ttl must be refused")
	}
	if _, err := runCLIErr(t, "scan", dir, "--offline", "--no-fail", "--cache-ttl", "soon"); err == nil {
		t.Fatal("an invalid --cache-ttl must be refused")
	}
}
