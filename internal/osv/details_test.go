package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/pkg/lockfile"
)

func TestCVSS3Score(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
		ok     bool
	}{
		// Published scores: Log4Shell, a typical RCE, an XSS, and a few others.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, true},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, true},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, true},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, true},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, true},
		// Not computed: other versions, and malformed vectors.
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0, false},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 0, false},
		{"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0, false},
		{"CVSS:3.1/AV:N", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		got, ok := cvss3Score(tt.vector)
		if ok != tt.ok || got != tt.want {
			t.Errorf("cvss3Score(%q) = %v, %v; want %v, %v", tt.vector, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSeverityOf(t *testing.T) {
	for score, want := range map[float64]string{0: "", 0.1: "low", 3.9: "low", 4.0: "medium", 6.9: "medium", 7.0: "high", 8.9: "high", 9.0: "critical", 10: "critical"} {
		if got := severityOf(score); got != want {
			t.Errorf("severityOf(%v) = %q, want %q", score, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.2.3", "1.2.3", 0, true},
		{"1.2.3", "1.2.10", -1, true},
		{"v1.10.0", "1.9.9", 1, true},
		{"1.2", "1.2.0", 0, true},
		{"1.0.0-rc.1", "1.0.0", -1, true},
		{"1.0.0", "1.0.0-rc.1", 1, true},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1, true},
		{"2.0.0rc1", "2.0.0", -1, true},
		{"1.0.0a2", "1.0.0b1", -1, true},
		{"1.0.0+build5", "1.0.0", 0, true},
		{"1.0.0.post1", "1.0.0", 0, true},
		{"2.0", "10.0", -1, true},
		{"abc", "1.0", 0, false},
		{"", "1.0", 0, false},
	}
	for _, tt := range tests {
		got, ok := compareVersions(tt.a, tt.b)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("compareVersions(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFixedForPicksTheRangeContainingTheVersion(t *testing.T) {
	ranges := []Range{
		{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "1.5.0"}, {Introduced: "2.0.0"}, {Fixed: "2.3.1"}}},
		{Type: "GIT", Events: []Event{{Introduced: "0"}, {Fixed: "deadbeef"}}},
	}
	tests := []struct {
		version string
		want    []string
	}{
		{"1.2.0", []string{"1.5.0"}},
		{"2.1.0", []string{"2.3.1"}},
		{"1.9.0", nil},
		{"2.3.1", nil},
		{"0.0.1", []string{"1.5.0"}},
	}
	for _, tt := range tests {
		if got := fixedFor(tt.version, ranges); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("fixedFor(%s) = %v, want %v", tt.version, got, tt.want)
		}
	}
	// An unparseable version cannot be placed in a range, so every candidate is offered.
	if got := fixedFor("main", ranges[:1]); len(got) != 2 {
		t.Errorf("fixedFor(main) = %v", got)
	}
}

const advisory = `{
  "id": "GHSA-1",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "database_specific": {"severity": "MODERATE"},
  "affected": [
    {"package": {"name": "lodash", "ecosystem": "npm"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
    {"package": {"name": "other", "ecosystem": "npm"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}
  ]
}`

func TestDetailsAndEnrich(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch strings.TrimPrefix(r.URL.Path, "/v1/vulns/") {
		case "GHSA-1":
			w.Write([]byte(advisory))
		case "GHSA-2":
			w.Write([]byte(`{"id":"GHSA-2","database_specific":{"severity":"MODERATE"}}`))
		case "BROKEN":
			w.Write([]byte(`{`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	c := &HTTPClient{Endpoint: srv.URL + "/v1/querybatch", HTTP: srv.Client()}
	got, err := c.Details(context.Background(), []string{"GHSA-1", "GHSA-1", "GHSA-2", "BROKEN", "MISSING"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("an advisory that cannot be read is left out, got %v", got)
	}
	if calls.Load() != 4 {
		t.Fatalf("each distinct advisory is fetched once, got %d requests", calls.Load())
	}
	if got["GHSA-1"].Severity != "critical" {
		t.Fatalf("a computed CVSS score wins over the database rating: %+v", got["GHSA-1"])
	}
	if got["GHSA-2"].Severity != "medium" {
		t.Fatalf("the database rating is the fallback: %+v", got["GHSA-2"])
	}

	dep := ecosystem.Dependency{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	enriched := Enrich(dep, lockfile.Vulnerability{ID: "GHSA-1"}, got["GHSA-1"])
	if enriched.Severity != lockfile.SeverityCritical || !reflect.DeepEqual(enriched.Fixed, []string{"4.17.21"}) {
		t.Fatalf("enriched = %+v", enriched)
	}
	// Advisories list several packages; only this package's fix applies.
	other := Enrich(ecosystem.Dependency{Ecosystem: "npm", Name: "unrelated", Version: "1.0.0"}, lockfile.Vulnerability{ID: "GHSA-1"}, got["GHSA-1"])
	if len(other.Fixed) != 0 {
		t.Fatalf("fixed = %v", other.Fixed)
	}
}

func TestVulnBase(t *testing.T) {
	if got := (&HTTPClient{}).vulnBase(); got != defaultVulnEndpoint {
		t.Fatalf("default = %s", got)
	}
	if got := (&HTTPClient{Endpoint: defaultEndpoint}).vulnBase(); got != defaultVulnEndpoint {
		t.Fatalf("derived = %s", got)
	}
	if got := (&HTTPClient{Endpoint: "http://127.0.0.1:1/v1/querybatch"}).vulnBase(); got != "http://127.0.0.1:1/v1/vulns/" {
		t.Fatalf("custom = %s", got)
	}
}
