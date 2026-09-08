package pypi_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/pypi"
)

func TestDependencies(t *testing.T) {
	eco := pypi.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected uv lockfile to be detected")
	}

	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deps, want 3: %#v", len(deps), deps)
	}

	got := map[string]string{}
	files := map[string]string{}
	for _, dep := range deps {
		got[dep.Name+"@"+dep.Version+"#"+dep.Filename] = dep.Digest
		files[dep.Filename] = dep.Name
	}
	if got["requests@2.32.3#requests-2.32.3.tar.gz"] != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("requests digest = %#v", got)
	}
	if _, ok := files["idna-3.10-py3-none-any.whl"]; !ok {
		t.Fatalf("missing any wheel: %#v", files)
	}
	if _, ok := files["idna-3.10-cp312-cp312-macosx_11_0_arm64.whl"]; !ok {
		t.Fatalf("missing macos wheel: %#v", files)
	}
}
