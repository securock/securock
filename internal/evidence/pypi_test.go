package evidence_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
	"github.com/securock/securock/pkg/lockfile"
)

func TestPyPIProvenancePresent(t *testing.T) {
	stmt, err := json.Marshal(map[string]any{
		"predicateType": "https://docs.pypi.org/attestations/publish/v1",
		"subject": []any{
			map[string]any{
				"name": "sampleproject-4.0.0.tar.gz",
				"digest": map[string]string{
					"sha256": strings.Repeat("ab", 32),
				},
			},
		},
		"predicate": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"version": 1,
		"attestation_bundles": []any{
			map[string]any{
				"publisher": map[string]any{
					"kind":       "GitHub",
					"repository": "pypa/sampleproject",
					"workflow":   "release.yml",
				},
				"attestations": []any{
					map[string]any{
						"version": 1,
						"envelope": map[string]any{
							"statement": base64.StdEncoding.EncodeToString(stmt),
							"signature": "AA==",
						},
					},
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integrity/sampleproject/4.0.0/sampleproject-4.0.0.tar.gz/provenance" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Accept"); !strings.Contains(got, "application/vnd.pypi.integrity.v1+json") {
			t.Errorf("accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/vnd.pypi.integrity.v1+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := &evidence.PyPI{HTTP: srv.Client(), Index: srv.URL, Limit: 1}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{{
		Ecosystem: "pypi",
		Name:      "sampleproject",
		Version:   "4.0.0",
		Filename:  "sampleproject-4.0.0.tar.gz",
		Digest:    "sha256:" + strings.Repeat("ab", 32),
		Registry:  "https://pypi.org",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := got[evidence.Key(ecosystem.Dependency{
		Ecosystem: "pypi",
		Name:      "sampleproject",
		Version:   "4.0.0",
		Filename:  "sampleproject-4.0.0.tar.gz",
	})]
	if !ok {
		t.Fatalf("missing record: %#v", got)
	}
	if rec.Provenance != lockfile.EvidencePresent || rec.Signature != lockfile.EvidencePresent {
		t.Fatalf("provenance/signature = %s/%s", rec.Provenance, rec.Signature)
	}
	if rec.Chain.Source != "github.com/pypa/sampleproject" {
		t.Fatalf("source = %q", rec.Chain.Source)
	}
	if rec.Chain.Workflow != "release.yml" {
		t.Fatalf("workflow = %q", rec.Chain.Workflow)
	}
	if rec.Chain.PredicateType != "https://docs.pypi.org/attestations/publish/v1" {
		t.Fatalf("predicate_type = %q", rec.Chain.PredicateType)
	}
}

func TestPyPIProvenanceMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &evidence.PyPI{HTTP: srv.Client(), Index: srv.URL, Limit: 1}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{{
		Ecosystem: "pypi",
		Name:      "nope",
		Version:   "1.0.0",
		Filename:  "nope-1.0.0.tar.gz",
		Registry:  "https://pypi.org",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec := got[evidence.Key(ecosystem.Dependency{
		Ecosystem: "pypi",
		Name:      "nope",
		Version:   "1.0.0",
		Filename:  "nope-1.0.0.tar.gz",
	})]
	if rec.Provenance != lockfile.EvidenceMissing {
		t.Fatalf("provenance = %s", rec.Provenance)
	}
}

func TestPyPISkipsPrivateRegistry(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &evidence.PyPI{HTTP: srv.Client(), Index: srv.URL, Limit: 1}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{{
		Ecosystem:  "pypi",
		Name:       "sampleproject",
		Version:    "4.0.0",
		Filename:   "sampleproject-4.0.0.tar.gz",
		Registry:   "https://pypi.company.example/simple",
		SourceKind: "registry",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("private registry must not query public Integrity API")
	}
	if len(got) != 0 {
		t.Fatalf("expected no records, got %#v", got)
	}
}

func TestPyPISkipsEmptyRegistry(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &evidence.PyPI{HTTP: srv.Client(), Index: srv.URL, Limit: 1}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{{
		Ecosystem: "pypi",
		Name:      "sampleproject",
		Version:   "4.0.0",
		Filename:  "sampleproject-4.0.0.tar.gz",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("empty registry must not query public Integrity API")
	}
	if len(got) != 0 {
		t.Fatalf("expected no records, got %#v", got)
	}
}

func TestPyPIGitLabPublisher(t *testing.T) {
	stmt, err := json.Marshal(map[string]any{
		"predicateType": "https://docs.pypi.org/attestations/publish/v1",
		"subject":       []any{},
		"predicate":     nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"version": 1,
		"attestation_bundles": []any{
			map[string]any{
				"publisher": map[string]any{
					"kind":              "GitLab",
					"repository":        "group/project",
					"workflow_filepath": ".gitlab-ci.yml",
				},
				"attestations": []any{
					map[string]any{
						"version": 1,
						"envelope": map[string]any{
							"statement": base64.StdEncoding.EncodeToString(stmt),
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c := &evidence.PyPI{HTTP: srv.Client(), Index: srv.URL, Limit: 1}
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{{
		Ecosystem: "pypi",
		Name:      "project",
		Version:   "1.0.0",
		Filename:  "project-1.0.0.tar.gz",
		Registry:  "https://pypi.org",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec := got[evidence.Key(ecosystem.Dependency{
		Ecosystem: "pypi",
		Name:      "project",
		Version:   "1.0.0",
		Filename:  "project-1.0.0.tar.gz",
	})]
	if rec.Chain.Source != "gitlab.com/group/project" {
		t.Fatalf("source = %q", rec.Chain.Source)
	}
	if rec.Chain.Workflow != ".gitlab-ci.yml" {
		t.Fatalf("workflow = %q", rec.Chain.Workflow)
	}
}

func TestPyPISubjectMatches(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	subjects := []*struct {
		Name   string
		Digest map[string]string
	}{
		{Name: "pkg-1.0.0.tar.gz", Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}},
	}
	// Use the package-level helper through attestation meta for coverage of filename bind.
	stmt, err := json.Marshal(map[string]any{
		"predicateType": "https://docs.pypi.org/attestations/publish/v1",
		"subject": []any{
			map[string]any{
				"name":   subjects[0].Name,
				"digest": subjects[0].Digest,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	att, err := json.Marshal(map[string]any{
		"version": 1,
		"envelope": map[string]any{
			"statement": base64.StdEncoding.EncodeToString(stmt),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pred, ok := evidence.PyPIAttestationMetaForTest(att, digest, "pkg-1.0.0.tar.gz")
	if !ok || pred != "https://docs.pypi.org/attestations/publish/v1" {
		t.Fatalf("meta = %q ok=%v", pred, ok)
	}
	if _, ok := evidence.PyPIAttestationMetaForTest(att, digest, "other-1.0.0.tar.gz"); ok {
		t.Fatal("filename mismatch must not match")
	}
}

func TestFillChainFromPublisherSAN(t *testing.T) {
	chain := evidence.FillChainFromPublisherSANForTest(
		"https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.3.0",
	)
	if chain.Source != "github.com/sigstore/sigstore-python" {
		t.Fatalf("source = %q", chain.Source)
	}
	if chain.Workflow != "release.yml" {
		t.Fatalf("workflow = %q", chain.Workflow)
	}
	if chain.Ref != "refs/tags/v4.3.0" {
		t.Fatalf("ref = %q", chain.Ref)
	}
	if !strings.Contains(chain.Builder, "sigstore-python") {
		t.Fatalf("builder = %q", chain.Builder)
	}
}

func TestPyPIVerifyLive(t *testing.T) {
	if testing.Short() {
		t.Skip("live PyPI Sigstore verification")
	}
	if os.Getenv("SECUROCK_LIVE_PYPI") != "1" {
		t.Skip("set SECUROCK_LIVE_PYPI=1 to run live Sigstore verification")
	}

	const (
		filename = "sigstore-4.3.0-py3-none-any.whl"
		digest   = "sha256:0f60c46c92fd4e871fbec979c9ae2aa381d7a93fbb774e49c9964550e5e16856"
	)
	c := evidence.NewPyPI()
	got, err := c.Collect(context.Background(), []ecosystem.Dependency{{
		Ecosystem: "pypi",
		Name:      "sigstore",
		Version:   "4.3.0",
		Filename:  filename,
		Digest:    digest,
		Registry:  "https://pypi.org",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec := got[evidence.Key(ecosystem.Dependency{
		Ecosystem: "pypi",
		Name:      "sigstore",
		Version:   "4.3.0",
		Filename:  filename,
	})]
	if rec.Provenance != lockfile.EvidenceVerified || rec.Signature != lockfile.EvidenceVerified {
		t.Fatalf("provenance/signature = %s/%s chain=%+v", rec.Provenance, rec.Signature, rec.Chain)
	}
	if rec.Chain.State != lockfile.EvidenceVerified {
		t.Fatalf("chain state = %s", rec.Chain.State)
	}
	if rec.Chain.Source != "github.com/sigstore/sigstore-python" {
		t.Fatalf("source = %q", rec.Chain.Source)
	}
	if rec.Chain.Workflow != "release.yml" {
		t.Fatalf("workflow = %q", rec.Chain.Workflow)
	}
}

func TestMultiPrefersFirstCollector(t *testing.T) {
	first := stubCollector{recs: map[string]evidence.Record{
		"npm:left@1": {Provenance: lockfile.EvidencePresent},
	}}
	second := stubCollector{recs: map[string]evidence.Record{
		"npm:left@1":   {Provenance: lockfile.EvidenceVerified},
		"pypi:right@1": {Provenance: lockfile.EvidencePresent},
	}}
	m := &evidence.Multi{Collectors: []evidence.Collector{first, second}}
	got, err := m.Collect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["npm:left@1"].Provenance != lockfile.EvidencePresent {
		t.Fatalf("first collector should win: %s", got["npm:left@1"].Provenance)
	}
	if got["pypi:right@1"].Provenance != lockfile.EvidencePresent {
		t.Fatalf("second collector unique key missing: %#v", got)
	}
}

type stubCollector struct {
	recs map[string]evidence.Record
}

func (s stubCollector) Collect(context.Context, []ecosystem.Dependency) (map[string]evidence.Record, error) {
	out := make(map[string]evidence.Record, len(s.recs))
	for k, v := range s.recs {
		out[k] = v
	}
	return out, nil
}
