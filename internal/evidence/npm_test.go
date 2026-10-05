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
			w.Write([]byte(`{
				"dist":{"signatures":[{"keyid":"abc","sig":"def"}],"tarball":"http://example.invalid/react.tgz"},
				"hasInstallScript": false,
				"_npmUser":{"name":"alice","email":"alice@example.com"},
				"maintainers":[{"name":"alice"},{"name":"bob"}]
			}`))
		case "/-/npm/v1/attestations/leftpad@1.0.0":
			http.NotFound(w, r)
		case "/leftpad/1.0.0":
			w.Write([]byte(`{
				"dist":{},
				"hasInstallScript": true,
				"scripts":{"postinstall":"node install.js"},
				"maintainers":[{"name":"leftpad-owner"}]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	c := &evidence.NPM{
		HTTP:        srv.Client(),
		Registry:    srv.URL,
		Limit:       2,
		SkipTarball: true,
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
	if react.Ownership.State != lockfile.CapChecked || react.Ownership.Publisher != "alice <alice@example.com>" {
		t.Fatalf("react ownership = %+v", react.Ownership)
	}
	if react.Capabilities.State != lockfile.CapChecked || react.Capabilities.InstallScripts == nil || *react.Capabilities.InstallScripts {
		t.Fatalf("react capabilities = %+v", react.Capabilities)
	}

	left := got[evidence.Key(ecosystem.Dependency{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"})]
	if left.Provenance != lockfile.EvidenceMissing || left.Signature != lockfile.EvidenceMissing {
		t.Fatalf("leftpad = %+v", left)
	}
	if left.Capabilities.InstallScripts == nil || !*left.Capabilities.InstallScripts {
		t.Fatalf("leftpad should have install scripts: %+v", left.Capabilities)
	}
	if left.Capabilities.Shell == nil || !*left.Capabilities.Shell {
		t.Fatalf("leftpad install scripts should imply shell: %+v", left.Capabilities)
	}
}
