package evidence_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/pkg/lockfile"
)

func TestNPMHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/old/1.0.0":
			w.Write([]byte(`{"dist":{},"license":"MIT","deprecated":"use new instead\nof this"}`))
		case "/old":
			w.Write([]byte(`{"time":{"created":"2012-01-01T00:00:00.000Z","1.0.0":"2013-05-06T07:08:09.123Z"},"versions":{"1.0.0":{}}}`))
		case "/legacy/2.0.0":
			w.Write([]byte(`{"dist":{},"license":{"type":"Apache-2.0","url":"https://example.com"},"deprecated":true}`))
		case "/fresh/3.0.0":
			w.Write([]byte(`{"dist":{}}`))
		case "/fresh":
			http.Error(w, "packument unavailable", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := &evidence.NPM{HTTP: srv.Client(), Registry: srv.URL, Limit: 2, SkipTarball: true}
	deps := []ecosystem.Dependency{
		{Ecosystem: "npm", Name: "old", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "legacy", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "fresh", Version: "3.0.0"},
		{Ecosystem: "npm", Name: "gone", Version: "4.0.0"},
	}
	got, err := c.Collect(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	health := func(i int) *lockfile.HealthEvidence { return got[evidence.Key(deps[i])].Health }

	old := health(0)
	if old == nil || old.Released != "2013-05-06" || old.License != "MIT" || old.Deprecated != "use new instead of this" {
		t.Fatalf("old = %+v", old)
	}
	legacy := health(1)
	if legacy == nil || legacy.License != "Apache-2.0" || legacy.Deprecated != "deprecated" || legacy.Released != "" {
		t.Fatalf("legacy = %+v", legacy)
	}
	fresh := health(2)
	if fresh == nil || *fresh != (lockfile.HealthEvidence{}) {
		t.Fatalf("a release with nothing to report still records that it was checked: %+v", fresh)
	}
	if gone := health(3); gone != nil {
		t.Fatalf("an unknown version must not claim health: %+v", gone)
	}
}

func TestNPMHealthIgnoresOversizedPackument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big/1.0.0":
			w.Write([]byte(`{"dist":{},"license":"ISC"}`))
		case "/big":
			w.Write([]byte(`{"time":{"1.0.0":"2020-01-01T00:00:00Z"},"padding":"` + strings.Repeat("x", 3<<20) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := &evidence.NPM{HTTP: srv.Client(), Registry: srv.URL, SkipTarball: true}
	dep := ecosystem.Dependency{Ecosystem: "npm", Name: "big", Version: "1.0.0"}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{dep})
	if err != nil {
		t.Fatal(err)
	}
	h := got[evidence.Key(dep)].Health
	if h == nil || h.License != "ISC" || h.Released != "" {
		t.Fatalf("the release date should be left unknown, not guessed: %+v", h)
	}
}

func TestPyPIHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/sample/1.0/json":
			w.Write([]byte(`{
				"info":{"license":"Some very long license text\nover lines","license_expression":"","classifiers":["Programming Language :: Python","License :: OSI Approved :: MIT License"],"yanked":false},
				"urls":[
					{"filename":"sample-1.0.tar.gz","upload_time_iso_8601":"2021-02-03T04:05:06.789012Z","yanked":false},
					{"filename":"sample-1.0-py3-none-any.whl","upload_time_iso_8601":"2021-02-04T00:00:00Z","yanked":true,"yanked_reason":"broken metadata"}
				]}`))
		case "/pypi/spdx/2.0/json":
			w.Write([]byte(`{"info":{"license_expression":"BSD-3-Clause OR Apache-2.0"},"urls":[{"filename":"spdx-2.0.tar.gz","upload_time_iso_8601":"2022-12-31T23:59:59Z"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := &evidence.PyPI{HTTP: srv.Client(), Index: srv.URL, Limit: 2}
	deps := []ecosystem.Dependency{
		{Ecosystem: "pypi", Name: "sample", Version: "1.0", Filename: "sample-1.0-py3-none-any.whl", Registry: "https://pypi.org/simple", SourceKind: "registry"},
		{Ecosystem: "pypi", Name: "spdx", Version: "2.0", Filename: "spdx-2.0.tar.gz", Registry: "https://pypi.org/simple", SourceKind: "registry"},
		{Ecosystem: "pypi", Name: "missing", Version: "1.0", Filename: "missing-1.0.tar.gz", Registry: "https://pypi.org/simple", SourceKind: "registry"},
	}
	got, err := c.Collect(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	want := []*lockfile.HealthEvidence{
		{Released: "2021-02-04", Deprecated: "yanked: broken metadata", License: "MIT"},
		{Released: "2022-12-31", License: "BSD-3-Clause OR Apache-2.0"},
		nil,
	}
	for i, dep := range deps {
		h := got[evidence.Key(dep)].Health
		switch {
		case want[i] == nil && h != nil:
			t.Fatalf("%s: expected no health, got %+v", dep.Name, h)
		case want[i] != nil && (h == nil || *h != *want[i]):
			t.Fatalf("%s: got %+v, want %+v", dep.Name, h, want[i])
		}
	}
}

func TestNPMReleaseFallsBackToDepsDevWhenThePackumentIsTooLarge(t *testing.T) {
	var depsDevCalls int
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big/1.0.0", "/@scope/big/1.0.0", "/@scope%2Fbig/1.0.0":
			w.Write([]byte(`{"dist":{},"license":"ISC"}`))
		case "/big", "/@scope%2Fbig":
			w.Write([]byte(`{"time":{"1.0.0":"2020-01-01T00:00:00Z"},"padding":"` + strings.Repeat("x", 3<<20) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(registry.Close)
	depsDev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		depsDevCalls++
		switch r.URL.EscapedPath() {
		case "/v3/systems/npm/packages/big/versions/1.0.0":
			w.Write([]byte(`{"publishedAt":"2023-04-05T06:07:08Z"}`))
		case "/v3/systems/npm/packages/@scope%2Fbig/versions/1.0.0":
			w.Write([]byte(`{"publishedAt":"2024-05-06T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(depsDev.Close)
	host := strings.TrimPrefix(registry.URL, "http://")

	collect := func(c *evidence.NPM, name string) *lockfile.HealthEvidence {
		dep := ecosystem.Dependency{Ecosystem: "npm", Name: name, Version: "1.0.0"}
		got, err := c.Collect(context.Background(), []ecosystem.Dependency{dep})
		if err != nil {
			t.Fatal(err)
		}
		return got[evidence.Key(dep)].Health
	}
	base := func() *evidence.NPM {
		return &evidence.NPM{HTTP: registry.Client(), Registry: registry.URL, SkipTarball: true, DepsDev: depsDev.URL, PublicHosts: []string{host}}
	}

	if h := collect(base(), "big"); h == nil || h.Released != "2023-04-05" || h.License != "ISC" {
		t.Fatalf("big = %+v", h)
	}
	if h := collect(base(), "@scope/big"); h == nil || h.Released != "2024-05-06" {
		t.Fatalf("a scoped name is escaped for deps.dev: %+v", h)
	}

	calls := depsDevCalls
	private := base()
	private.PublicHosts = []string{"registry.npmjs.org"}
	if h := collect(private, "big"); h == nil || h.Released != "" {
		t.Fatalf("a registry deps.dev does not cover is never looked up there: %+v", h)
	}
	off := base()
	off.DepsDev = ""
	if h := collect(off, "big"); h == nil || h.Released != "" {
		t.Fatalf("an empty DepsDev turns the fallback off: %+v", h)
	}
	if depsDevCalls != calls {
		t.Fatalf("deps.dev was called %d times when it should not have been", depsDevCalls-calls)
	}

	// deps.dev does not know the version either: the date stays unknown.
	missing := base()
	dep := ecosystem.Dependency{Ecosystem: "npm", Name: "big", Version: "9.9.9"}
	got, err := missing.Collect(context.Background(), []ecosystem.Dependency{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[evidence.Key(dep)].Health; h != nil && h.Released != "" {
		t.Fatalf("health = %+v", h)
	}
}

func TestNPMReleasePrefersThePackumentWhenItFits(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/small/1.0.0":
			w.Write([]byte(`{"dist":{}}`))
		case "/small":
			w.Write([]byte(`{"time":{"1.0.0":"2019-02-03T00:00:00Z"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(registry.Close)
	depsDev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("deps.dev must not be called when the package document is readable: %s", r.URL)
	}))
	t.Cleanup(depsDev.Close)

	c := &evidence.NPM{HTTP: registry.Client(), Registry: registry.URL, SkipTarball: true, DepsDev: depsDev.URL, PublicHosts: []string{strings.TrimPrefix(registry.URL, "http://")}}
	dep := ecosystem.Dependency{Ecosystem: "npm", Name: "small", Version: "1.0.0"}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[evidence.Key(dep)].Health; h == nil || h.Released != "2019-02-03" {
		t.Fatalf("health = %+v", h)
	}
}
