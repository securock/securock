package evidence_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
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
			w.Write([]byte(`{
				"attestations":[{
					"predicateType":"https://slsa.dev/provenance/v1",
					"predicate":{
						"buildDefinition":{
							"resolvedDependencies":[{
								"uri":"git+https://github.com/facebook/react",
								"digest":{"sha1":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
							}],
							"externalParameters":{
								"workflow":{"path":".github/workflows/release.yml"}
							}
						},
						"runDetails":{"builder":{"id":"https://github.com/actions/runner"}}
					}
				}]
			}`))
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
	if react.Chain.State != lockfile.EvidencePresent || react.Chain.Source != "github.com/facebook/react" {
		t.Fatalf("react chain = %+v", react.Chain)
	}
	if react.Chain.Workflow != "release.yml" {
		t.Fatalf("react workflow = %q", react.Chain.Workflow)
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
	if left.Chain.State != lockfile.EvidenceMissing {
		t.Fatalf("leftpad chain = %+v", left.Chain)
	}
	if left.Capabilities.InstallScripts == nil || !*left.Capabilities.InstallScripts {
		t.Fatalf("leftpad should have install scripts: %+v", left.Capabilities)
	}
	if left.Capabilities.Shell == nil || !*left.Capabilities.Shell {
		t.Fatalf("leftpad install scripts should imply shell: %+v", left.Capabilities)
	}
}

func TestNPMTarballScanDigestBound(t *testing.T) {
	tarball := mustTestTarball(t, "package/index.js", []byte("require('child_process').exec('id');\n"))
	sum := sha512.Sum512(tarball)
	digest := "sha512:" + hex.EncodeToString(sum[:])

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/npm/v1/attestations/evil@1.0.0":
			http.NotFound(w, r)
		case "/evil/1.0.0":
			w.Write([]byte(`{
				"dist":{"tarball":"` + srvURL + `/evil-1.0.0.tgz"},
				"hasInstallScript": false
			}`))
		case "/evil-1.0.0.tgz":
			w.Write(tarball)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	c := &evidence.NPM{HTTP: srv.Client(), Registry: srv.URL, Limit: 1}

	ok := gotNPM(t, c, ecosystem.Dependency{
		Ecosystem: "npm", Name: "evil", Version: "1.0.0", Digest: digest,
	})
	if ok.Capabilities.State != lockfile.CapChecked {
		t.Fatalf("matched digest should be checked: %+v", ok.Capabilities)
	}
	if ok.Capabilities.Shell == nil || !*ok.Capabilities.Shell {
		t.Fatalf("source shell use not detected: %+v", ok.Capabilities)
	}

	mismatch := gotNPM(t, c, ecosystem.Dependency{
		Ecosystem: "npm", Name: "evil", Version: "1.0.0",
		Digest: "sha512:" + hex.EncodeToString(bytes.Repeat([]byte{0}, 64)),
	})
	if mismatch.Capabilities.State != lockfile.CapUnknown {
		t.Fatalf("digest mismatch must stay unknown: %+v", mismatch.Capabilities)
	}

	missing := gotNPM(t, c, ecosystem.Dependency{
		Ecosystem: "npm", Name: "evil", Version: "1.0.0",
	})
	if missing.Capabilities.State != lockfile.CapUnknown {
		t.Fatalf("missing digest must stay unknown: %+v", missing.Capabilities)
	}
}

func TestNPMTarballScanFailClosed(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/npm/v1/attestations/broken@1.0.0":
			http.NotFound(w, r)
		case "/broken/1.0.0":
			w.Write([]byte(`{
				"dist":{"tarball":"` + srvURL + `/broken.tgz"},
				"hasInstallScript": false
			}`))
		case "/broken.tgz":
			w.Write([]byte("not-a-tarball"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	sum := sha512.Sum512([]byte("not-a-tarball"))
	c := &evidence.NPM{HTTP: srv.Client(), Registry: srv.URL, Limit: 1}
	got := gotNPM(t, c, ecosystem.Dependency{
		Ecosystem: "npm", Name: "broken", Version: "1.0.0",
		Digest: "sha512:" + hex.EncodeToString(sum[:]),
	})
	if got.Capabilities.State != lockfile.CapUnknown || got.Behavior.State != lockfile.CapUnknown {
		t.Fatalf("scan failure must stay unknown: caps=%+v beh=%+v", got.Capabilities, got.Behavior)
	}
}

func gotNPM(t *testing.T, c *evidence.NPM, dep ecosystem.Dependency) evidence.Record {
	t.Helper()
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{dep})
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := got[evidence.Key(dep)]
	if !ok {
		t.Fatal("missing record")
	}
	return rec
}

func mustTestTarball(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
