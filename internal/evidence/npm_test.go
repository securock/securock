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

func TestNPMEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/npm/v1/attestations/react@19.2.0":
			w.Write([]byte(`{"attestations":[{"predicateType":"https://slsa.dev/provenance/v1"}]}`))
		case "/react/19.2.0":
			w.Write([]byte(`{"dist":{"signatures":[{"keyid":"abc","sig":"def"}]}}`))
		case "/-/npm/v1/attestations/leftpad@1.0.0":
			http.NotFound(w, r)
		case "/leftpad/1.0.0":
			w.Write([]byte(`{"dist":{}}`))
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

	react := got[evidence.Key(ecosystem.Dependency{Ecosystem: "npm", Name: "react", Version: "19.2.0"})]
	if react.Provenance != lockfile.EvidencePresent || react.Signature != lockfile.EvidencePresent {
		t.Fatalf("react = %+v", react)
	}
	left := got[evidence.Key(ecosystem.Dependency{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"})]
	if left.Provenance != lockfile.EvidenceMissing || left.Signature != lockfile.EvidenceMissing {
		t.Fatalf("leftpad = %+v", left)
	}
}
