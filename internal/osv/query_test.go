package osv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/osv"
)

func TestQuerySendsBatchesTogether(t *testing.T) {
	// The HTTP cache lives under the user cache dir; keep it out of the real one.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	var inflight, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		// Hold the request until a second one arrives; serial batches never get there.
		deadline := time.Now().Add(2 * time.Second)
		for inflight.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}

		var req struct {
			Queries []struct {
				Version string `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type result struct {
			Vulns []map[string]string `json:"vulns"`
		}
		var res struct {
			Results []result `json:"results"`
		}
		for _, q := range req.Queries {
			res.Results = append(res.Results, result{Vulns: []map[string]string{{"id": "GHSA-" + q.Version}}})
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	defer srv.Close()

	var deps []ecosystem.Dependency
	for i := 0; i < 250; i++ {
		deps = append(deps, ecosystem.Dependency{Ecosystem: "npm", Name: "pkg", Version: fmt.Sprintf("1.0.%d", i)})
	}
	client := &osv.HTTPClient{Endpoint: srv.URL + "/v1/querybatch"}
	got, err := client.Query(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() < 2 {
		t.Fatalf("peak in-flight requests = %d, want at least 2", peak.Load())
	}
	if len(got) != len(deps) {
		t.Fatalf("got %d results, want %d", len(got), len(deps))
	}
	for _, dep := range deps {
		vulns := got[ecosystem.Identity(dep)]
		if len(vulns) != 1 || vulns[0].ID != "GHSA-"+dep.Version {
			t.Fatalf("%s: vulns = %+v", dep.Version, vulns)
		}
	}
}
