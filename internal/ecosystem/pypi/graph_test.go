package pypi_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/pypi"
)

func TestScopeAndEdges(t *testing.T) {
	dir := t.TempDir()
	lock := `version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "requests" },
]

[package.optional-dependencies]
fast = [
    { name = "ujson" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "urllib3", version = "2.2.0", marker = "python_version >= '3.8'" },
]
sdist = { url = "https://files.pythonhosted.org/packages/requests-2.32.3.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }

[[package]]
name = "idna"
version = "3.10"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/idna-3.10-py3-none-any.whl", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" },
    { url = "https://files.pythonhosted.org/packages/idna-3.10-other.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
]

[[package]]
name = "urllib3"
version = "2.2.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/urllib3-2.2.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }

[[package]]
name = "ujson"
version = "5.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/ujson-5.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "pluggy" },
]
sdist = { url = "https://files.pythonhosted.org/packages/pytest-8.0.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }

[[package]]
name = "pluggy"
version = "1.4.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/pluggy-1.4.0.tar.gz", hash = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }
`
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := pypi.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string]core.Dependency{}
	for _, dep := range list {
		byFile[dep.Name+"/"+dep.Filename] = dep
	}
	scope := func(key string) string {
		t.Helper()
		dep, ok := byFile[key]
		if !ok {
			t.Fatalf("%s not found in %v", key, list)
		}
		return dep.Scope
	}

	if got := scope("requests/requests-2.32.3.tar.gz"); got != core.ScopeRuntime {
		t.Errorf("requests = %q", got)
	}
	// idna is a runtime dependency of requests and a dev dependency of pytest: runtime wins,
	// and it applies to every wheel of the package.
	for _, key := range []string{"idna/idna-3.10-py3-none-any.whl", "idna/idna-3.10-other.whl", "urllib3/urllib3-2.2.0.tar.gz"} {
		if got := scope(key); got != core.ScopeRuntime {
			t.Errorf("%s = %q", key, got)
		}
	}
	if got := scope("ujson/ujson-5.0.0.tar.gz"); got != core.ScopeOptional {
		t.Errorf("ujson = %q", got)
	}
	for _, key := range []string{"pytest/pytest-8.0.0.tar.gz", "pluggy/pluggy-1.4.0.tar.gz"} {
		if got := scope(key); got != core.ScopeDev {
			t.Errorf("%s = %q", key, got)
		}
	}

	// Edges are recorded once per package, to the first artifact of each dependency.
	edges := byFile["requests/requests-2.32.3.tar.gz"].DependsOn
	if len(edges) != 2 || edges[0] != "pypi:idna@3.10#idna-3.10-py3-none-any.whl" || edges[1] != "pypi:urllib3@2.2.0#urllib3-2.2.0.tar.gz" {
		t.Errorf("requests edges = %v", edges)
	}
	if got := byFile["idna/idna-3.10-other.whl"].DependsOn; len(got) != 0 {
		t.Errorf("a second wheel carries no edges: %v", got)
	}
}
