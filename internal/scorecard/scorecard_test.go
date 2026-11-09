package scorecard_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/internal/scorecard"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/securock/securock/pkg/policy"
)

// server fakes the two deps.dev endpoints by the path it is asked for.
func server(t *testing.T, routes map[string]func(w http.ResponseWriter)) (*scorecard.Client, *atomic.Int32) {
	t.Helper()
	httpx.Configure(true, 0)
	t.Cleanup(func() { httpx.Configure(false, 0) })
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if h, ok := routes[r.URL.EscapedPath()]; ok {
			h(w)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := scorecard.New()
	c.Base = srv.URL
	return c, &calls
}

func body(s string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.Write([]byte(s)) }
}

func status(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

func related(provenance string) string {
	return `{"relatedProjects":[
		{"projectKey":{"id":"github.com/o/issues"},"relationType":"ISSUE_TRACKER","relationProvenance":"UNVERIFIED_METADATA"},
		{"projectKey":{"id":"github.com/o/r"},"relationType":"SOURCE_REPO","relationProvenance":"` + provenance + `"}]}`
}

func TestLookup(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/claimed/versions/1.0.0":     body(related("UNVERIFIED_METADATA")),
		"/v3/systems/npm/packages/verified/versions/1.0.0":    body(related("VERIFIED_METADATA")),
		"/v3/systems/npm/packages/@s%2Fscoped/versions/2.0.0": body(related("UNVERIFIED_METADATA")),
		"/v3/systems/npm/packages/norepo/versions/1.0.0":      body(`{"relatedProjects":[]}`),
		"/v3/systems/npm/packages/noscore/versions/1.0.0":     body(`{"relatedProjects":[{"projectKey":{"id":"github.com/o/none"},"relationType":"SOURCE_REPO"}]}`),
		"/v3/systems/npm/packages/outofrange/versions/1.0.0":  body(`{"relatedProjects":[{"projectKey":{"id":"github.com/o/odd"},"relationType":"SOURCE_REPO"}]}`),
		"/v3/projects/github.com%2Fo%2Fr":                     body(`{"scorecard":{"overallScore":3.5}}`),
		"/v3/projects/github.com%2Fo%2Fnone":                  body(`{"scorecard":null}`),
		"/v3/projects/github.com%2Fo%2Fodd":                   body(`{"scorecard":{"overallScore":42}}`),
	})
	targets := []scorecard.Target{
		{"npm", "claimed", "1.0.0"},
		{"npm", "verified", "1.0.0"},
		{"npm", "@s/scoped", "2.0.0"},
		{"npm", "norepo", "1.0.0"},
		{"npm", "noscore", "1.0.0"},
		{"npm", "outofrange", "1.0.0"},
		{"npm", "unknown-package", "1.0.0"},
		{"maven", "unsupported", "1.0.0"},
		{"npm", "no-version", ""},
	}
	found, failed := c.Lookup(t.Context(), targets)
	if len(failed) != 0 {
		t.Fatalf("a 404 and a missing score are answers, not failures: %v", failed)
	}
	want := map[scorecard.Target]scorecard.Result{
		{"npm", "claimed", "1.0.0"}:   {Repository: "github.com/o/r", Score: 3.5},
		{"npm", "verified", "1.0.0"}:  {Repository: "github.com/o/r", Score: 3.5, Verified: true},
		{"npm", "@s/scoped", "2.0.0"}: {Repository: "github.com/o/r", Score: 3.5},
	}
	if len(found) != len(want) {
		t.Fatalf("found %+v, want %+v", found, want)
	}
	for k, v := range want {
		got := found[k]
		if got.Repository != v.Repository || got.Score != v.Score || got.Verified != v.Verified {
			t.Errorf("%v = %+v, want %+v", k, got, v)
		}
	}
}

func TestLookupReportsFailures(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/down/versions/1.0.0":    status(500),
		"/v3/systems/npm/packages/limited/versions/1.0.0": status(429),
		"/v3/systems/npm/packages/garbage/versions/1.0.0": body("nope"),
		"/v3/systems/npm/packages/halfway/versions/1.0.0": body(related("UNVERIFIED_METADATA")),
		"/v3/projects/github.com%2Fo%2Fr":                 status(503),
	})
	var targets []scorecard.Target
	for _, n := range []string{"down", "limited", "garbage", "halfway"} {
		targets = append(targets, scorecard.Target{Ecosystem: "npm", Name: n, Version: "1.0.0"})
	}
	found, failed := c.Lookup(t.Context(), targets)
	if len(found) != 0 || len(failed) != 4 {
		t.Fatalf("every failed request must be reported: found %+v, failed %v", found, failed)
	}
}

func TestLookupAsksOncePerTarget(t *testing.T) {
	c, calls := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/a/versions/1.0.0": body(`{"relatedProjects":[]}`),
	})
	target := scorecard.Target{Ecosystem: "npm", Name: "a", Version: "1.0.0"}
	c.Lookup(t.Context(), []scorecard.Target{target, target, target})
	if n := calls.Load(); n != 1 {
		t.Fatalf("a duplicated target is looked up once, got %d requests", n)
	}
}

func TestLookupSendsNothingForUnsupportedEcosystems(t *testing.T) {
	c, calls := server(t, nil)
	c.Lookup(t.Context(), []scorecard.Target{{"maven", "x", "1"}, {"swift", "y", "1"}})
	if calls.Load() != 0 {
		t.Fatal("deps.dev must not be asked about ecosystems it is not mapped for")
	}
	for eco := range scorecard.Systems {
		if strings.ToLower(eco) != eco {
			t.Errorf("ecosystem keys are lowercase: %q", eco)
		}
	}
}

func doc(arts ...lockfile.Artifact) lockfile.Document { return lockfile.Document{Artifacts: arts} }

func art(eco, name, version, registry string) lockfile.Artifact {
	return lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: eco, Name: name},
		Version: version,
		Source:  lockfile.ArtifactSource{Registry: registry},
	}
}

func TestCollect(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/pub/versions/1.0.0":  body(related("UNVERIFIED_METADATA")),
		"/v3/systems/npm/packages/priv/versions/1.0.0": body(related("UNVERIFIED_METADATA")),
		"/v3/projects/github.com%2Fo%2Fr":              body(`{"scorecard":{"overallScore":6}}`),
	})
	const public = "https://registry.npmjs.org"
	d := doc(
		art("npm", "pub", "1.0.0", public),
		art("npm", "priv", "1.0.0", "https://npm.corp.example"),
		art("npm", "norecord", "1.0.0", ""),
		art("maven", "unsupported", "1.0.0", "https://repo.maven.apache.org/maven2"),
	)

	got, note := c.Collect(t.Context(), policy.Network{Mode: policy.ModePublicOnly}, d)
	if len(got) != 1 || got["npm:pub@1.0.0"].Score != 6 {
		t.Fatalf("only the public package is looked up: %+v", got)
	}
	if !strings.Contains(note, "3 of 4 packages have no Scorecard") {
		t.Fatalf("the packages without a score must be counted: %q", note)
	}

	// allow-all sends the private registry's package too.
	got, _ = c.Collect(t.Context(), policy.Network{Mode: policy.ModeAllowAll}, d)
	if _, ok := got["npm:priv@1.0.0"]; !ok {
		t.Fatalf("allow-all should look up every supported package: %+v", got)
	}
}

func TestCollectOfflineSendsNothing(t *testing.T) {
	c, calls := server(t, nil)
	got, note := c.Collect(t.Context(), policy.Network{Mode: policy.ModeOffline}, doc(art("npm", "a", "1.0.0", "https://registry.npmjs.org")))
	if len(got) != 0 || !strings.Contains(note, "offline") || calls.Load() != 0 {
		t.Fatalf("offline must not look anything up: %+v %q %d", got, note, calls.Load())
	}
}

func TestCollectCountsFailures(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/a/versions/1.0.0": status(500),
	})
	_, note := c.Collect(t.Context(), policy.Network{Mode: policy.ModePublicOnly}, doc(art("npm", "a", "1.0.0", "https://registry.npmjs.org")))
	if !strings.Contains(note, "1 lookups failed") {
		t.Fatalf("a failed lookup must be reported: %q", note)
	}
}

func TestCollectNoteEmptyWhenEveryPackageHasAScore(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/a/versions/1.0.0": body(related("VERIFIED_METADATA")),
		"/v3/projects/github.com%2Fo%2Fr":           body(`{"scorecard":{"overallScore":9}}`),
	})
	got, note := c.Collect(t.Context(), policy.Network{Mode: policy.ModePublicOnly}, doc(art("npm", "a", "1.0.0", "https://registry.npmjs.org")))
	if len(got) != 1 || note != "" {
		t.Fatalf("nothing to report: %+v %q", got, note)
	}
}

func TestLookupReadsIndividualChecks(t *testing.T) {
	c, _ := server(t, map[string]func(http.ResponseWriter){
		"/v3/systems/npm/packages/a/versions/1.0.0": body(related("UNVERIFIED_METADATA")),
		"/v3/projects/github.com%2Fo%2Fr": body(`{"scorecard":{"overallScore":6,"checks":[
			{"name":"Maintained","score":10},
			{"name":"Dangerous-Workflow","score":0},
			{"name":"Packaging","score":-1},
			{"name":"Fuzzing","score":null},
			{"name":"SAST","score":42}]}}`),
	})
	target := scorecard.Target{Ecosystem: "npm", Name: "a", Version: "1.0.0"}
	found, _ := c.Lookup(t.Context(), []scorecard.Target{target})
	checks := found[target].Checks
	if len(checks) != 2 || checks["Maintained"] != 10 || checks["Dangerous-Workflow"] != 0 {
		t.Fatalf("a not-applicable (-1), missing or out-of-range score is left out, and 0 is kept: %v", checks)
	}
}
