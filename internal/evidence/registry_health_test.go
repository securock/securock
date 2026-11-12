package evidence_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/pkg/lockfile"
)

func TestPublicRegistryHealthWithoutInventedSignatures(t *testing.T) {
	httpx.Configure(true, 0)
	defer httpx.Configure(false, 0)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/example.org/lib/@v/v1.0.0.info":
			w.Write([]byte(`{"Version":"v1.0.0","Time":"2026-01-02T12:00:00Z"}`))
		case "/api/v1/crates/example/1.0.0":
			w.Write([]byte(`{"version":{"num":"1.0.0","license":"MIT","created_at":"2026-01-02T00:00:00Z","yanked":true}}`))
		case "/v3/registration5-gz-semver2/example/1.0.0.json":
			w.Write([]byte(`{"catalogEntry":{"id":"Example","version":"1.0.0","licenseExpression":"Apache-2.0","published":"2026-01-02T00:00:00Z","deprecation":{"reasons":["Legacy"]}}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := evidence.NewRegistryHealth()
	c.HTTP = server.Client()
	c.GoProxy = server.URL
	c.Crates = server.URL
	c.NuGet = server.URL
	deps := []ecosystem.Dependency{
		{Ecosystem: "go", SourceKind: "registry", Registry: "https://proxy.golang.org", Name: "example.org/lib", Version: "v1.0.0"},
		{Ecosystem: "cargo", SourceKind: "registry", Registry: "https://index.crates.io", Name: "example", Version: "1.0.0"},
		{Ecosystem: "nuget", SourceKind: "registry", Registry: "https://api.nuget.org", Name: "Example", Version: "1.0.0"},
	}
	got, e := c.Collect(context.Background(), deps)
	if e != nil || len(got) != 3 || requests.Load() != 3 {
		t.Fatal(got, e, requests.Load())
	}
	for _, dep := range deps {
		r := got[evidence.Key(dep)]
		if r.Signature != lockfile.EvidenceUnknown || r.Provenance != lockfile.EvidenceUnknown || r.Health == nil || r.Health.Released != "2026-01-02" {
			t.Fatal(dep, r)
		}
	}
	if got[evidence.Key(deps[1])].Health.Deprecated != "yanked" || got[evidence.Key(deps[2])].Health.License != "Apache-2.0" {
		t.Fatal(got)
	}
	deps[0].Registry = "https://private.example"
	deps[1].SourceKind = "git"
	deps[2].Registry = "https://private.example"
	got, e = c.Collect(context.Background(), deps)
	if e != nil || len(got) != 0 || requests.Load() != 3 {
		t.Fatal("private source leaked", got, e, requests.Load())
	}
}
