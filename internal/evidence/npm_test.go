package evidence_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/pkg/lockfile"
)

func TestNPMProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/npm/v1/attestations/react@19.2.0":
			w.Write([]byte(`{"attestations":[{"predicateType":"https://slsa.dev/provenance/v1"}]}`))
		case "/-/npm/v1/attestations/leftpad@1.0.0":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := &evidence.NPM{
		HTTP:     srv.Client(),
		Registry: srv.URL,
		Limit:    2,
	}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{
		{Ecosystem: "npm", Name: "react", Version: "19.2.0"},
		{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"},
		{Ecosystem: "cargo", Name: "serde", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[evidence.Key(ecosystem.Dependency{Ecosystem: "npm", Name: "react", Version: "19.2.0"})] != lockfile.EvidenceVerified {
		t.Fatalf("react = %s", got["npm:react@19.2.0"])
	}
	if got[evidence.Key(ecosystem.Dependency{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"})] != lockfile.EvidenceMissing {
		t.Fatalf("leftpad = %s", got["npm:leftpad@1.0.0"])
	}
}
