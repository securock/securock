package osv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/osv"
)

func TestQueryPagination(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	type query struct {
		Package   struct{ Name, Ecosystem string }
		Version   string
		PageToken string `json:"page_token"`
	}
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Queries []query }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		calls++
		var wantNames, wantTokens []string
		var response string
		switch calls {
		case 1:
			wantNames, wantTokens = []string{"first", "clean", "last"}, []string{"", "", ""}
			response = `{"results":[{"vulns":[{"id":"GHSA-z"}],"next_page_token":"first-1"},{},{"next_page_token":"last-1"}]}`
		case 2:
			wantNames, wantTokens = []string{"first", "last"}, []string{"first-1", "last-1"}
			response = `{"results":[{"vulns":[{"id":"GHSA-a"},{"id":"GHSA-z"}],"next_page_token":"first-2"},{"vulns":[{"id":"MAL-last"}]}]}`
		case 3:
			wantNames, wantTokens = []string{"first"}, []string{"first-2"}
			response = `{"results":[{"vulns":[{"id":"GHSA-b"}]}]}`
		default:
			t.Error("unexpected extra request")
			http.Error(w, "extra request", http.StatusBadRequest)
			return
		}
		var names, tokens []string
		for _, q := range req.Queries {
			names, tokens = append(names, q.Package.Name), append(tokens, q.PageToken)
			if q.Package.Ecosystem != "npm" || q.Version != "1.0.0" {
				t.Errorf("query lost package identity: %+v", q)
			}
		}
		if !slices.Equal(names, wantNames) || !slices.Equal(tokens, wantTokens) {
			t.Errorf("queries = %v / %v, want %v / %v", names, tokens, wantNames, wantTokens)
		}
		fmt.Fprint(w, response)
	}))
	defer srv.Close()
	var deps []ecosystem.Dependency
	for _, name := range []string{"first", "clean", "last"} {
		deps = append(deps, ecosystem.Dependency{Ecosystem: "npm", Name: name, Version: "1.0.0"})
	}
	client := &osv.HTTPClient{Endpoint: srv.URL + "/v1/querybatch"}
	got, err := client.Query(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("requests = %d, want 3", calls)
	}
	for i, want := range [][]string{{"GHSA-a", "GHSA-b", "GHSA-z"}, {}, {"MAL-last"}} {
		vulns, ok := got[ecosystem.Identity(deps[i])]
		var ids []string
		for _, v := range vulns {
			ids = append(ids, v.ID)
		}
		if !ok || !slices.Equal(ids, want) {
			t.Errorf("%s: ids = %v (present %t), want %v", deps[i].Name, ids, ok, want)
		}
	}
}

func TestQueryRejectsIncompleteResults(t *testing.T) {
	for _, tt := range []struct{ name, response, wantError string }{
		{"missing result", `{"results":[]}`, "result count"},
		{"null result", `{"results":[null]}`, "missing result"},
		{"missing ID", `{"results":[{"vulns":[{}]}]}`, "missing vulnerability ID"},
		{"null vulnerability", `{"results":[{"vulns":[null]}]}`, "missing vulnerability ID"},
		{"repeated token", `{"results":[{"next_page_token":"again"}]}`, "repeated page token"},
		{"token cycle", `{"results":[{"next_page_token":"again"}]}`, "repeated page token"},
		{"later HTTP failure", "", "unexpected status"},
		{"later malformed JSON", `{`, "osv query:"},
		{"later count mismatch", `{"results":[]}`, "result count"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if strings.HasPrefix(tt.name, "later ") && calls == 1 {
					fmt.Fprint(w, `{"results":[{"vulns":[{"id":"GHSA-first"}],"next_page_token":"next"}]}`)
					return
				}
				if tt.name == "token cycle" && calls == 2 {
					fmt.Fprint(w, `{"results":[{"next_page_token":"other"}]}`)
					return
				}
				if calls > 4 || tt.response == "" {
					http.Error(w, "incomplete", http.StatusBadRequest)
					return
				}
				fmt.Fprint(w, tt.response)
			}))
			defer srv.Close()
			client := &osv.HTTPClient{Endpoint: srv.URL + "/v1/querybatch"}
			got, err := client.Query(context.Background(), []ecosystem.Dependency{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) || got != nil {
				t.Fatalf("Query = %v, %v; want no result and error containing %q", got, err, tt.wantError)
			}
		})
	}
}

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
