package golang_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/golang"
)

func TestDependencies(t *testing.T) {
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

	got := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version] = dep.Digest
	}
	if _, ok := got["github.com/spf13/cobra@v1.9.1"]; !ok {
		t.Fatalf("missing cobra: %#v", got)
	}
	if _, ok := got["golang.org/x/sys@v0.0.0-20220811171246-acb485596380"]; !ok {
		t.Fatalf("missing sys: %#v", got)
	}
}
