package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/securock/securock/internal/osv"
)

func TestDetailsCVEs(t *testing.T) {
	records := map[string]string{
		"GHSA-aaaa":  `{"id":"GHSA-aaaa","aliases":["cve-2024-0002","CVE-2024-0001","GHSA-bbbb"," CVE-2024-0001 "]}`,
		"CVE-2024-9": `{"id":"CVE-2024-9","aliases":[]}`,
		"PYSEC-1":    `{"id":"PYSEC-1"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/v1/vulns/"):]
		raw, ok := records[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(raw))
	}))
	defer srv.Close()

	c := osv.New()
	c.Endpoint = srv.URL + "/v1/querybatch"
	got, err := c.Details(context.Background(), []string{"GHSA-aaaa", "CVE-2024-9", "PYSEC-1"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"GHSA-aaaa":  {"CVE-2024-0001", "CVE-2024-0002"},
		"CVE-2024-9": {"CVE-2024-9"},
		"PYSEC-1":    nil,
	}
	for id, cves := range want {
		if !reflect.DeepEqual(got[id].CVEs, cves) {
			t.Errorf("%s: CVEs = %v, want %v", id, got[id].CVEs, cves)
		}
	}
}
