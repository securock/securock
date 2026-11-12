package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/schemas"
)

func TestDASTOfflineAndPublicOnlyNeverContactTarget(t *testing.T) {
	isolateHome(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, prefix := range [][]string{{"dast", srv.URL}, {"security", t.TempDir(), "--target", srv.URL}} {
		for _, flags := range [][]string{{}, {"--offline"}, {"--network", "offline"}, {"--network", "allow-all", "--offline"}} {
			args := append(append([]string{}, prefix...), flags...)
			if _, err := execCLI(t, "", args...); err == nil {
				t.Errorf("expected network refusal: %v", args)
			}
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("offline/public-only sent %d requests", hits.Load())
	}
}

func TestDASTJSONThresholdsAndExceptions(t *testing.T) {
	isolateHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "text/html") }))
	defer srv.Close()
	ex := filepath.Join(t.TempDir(), "exceptions.yaml")
	raw, err := execCLI(t, "", "dast", srv.URL, "--network", "allow-all", "--format", "json", "--exceptions", ex)
	if err == nil || !strings.Contains(err.Error(), "findings at or above high") {
		t.Fatalf("expected severity failure: %v", err)
	}
	if err := schemas.Validate("dast-report.schema.json", raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	runCLI(t, "accept", "dast:unencrypted-http", t.TempDir(), "--subject", srv.URL+"/", "--exceptions", ex, "--reason", "local development server", "--expires", "2999-12-31")
	raw = runCLI(t, "dast", srv.URL, "--network", "allow-all", "--format", "json", "--exceptions", ex)
	var report finding.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Suppressed() != 1 {
		t.Fatalf("accepted finding missing: %s", raw)
	}
	for _, format := range []string{"text", "sarif", "junit", "markdown"} {
		runCLI(t, "dast", srv.URL, "--network", "allow-all", "--format", format, "--no-fail", "--exceptions", ex)
	}
}

func TestDASTIncompleteWritesReportDespiteNoFail(t *testing.T) {
	isolateHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	output := filepath.Join(t.TempDir(), "dast.json")
	_, err := execCLI(t, "", "dast", srv.URL, "--network", "allow-all", "--no-fail", "--format", "json", "--output", output)
	if err == nil || !strings.Contains(err.Error(), "DAST analysis incomplete") {
		t.Fatalf("expected operational error: %v", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.Validate("dast-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "dast:analysis-incomplete") {
		t.Fatalf("missing incomplete coverage: %s", raw)
	}
}

func TestSecurityDASTMergesAndPreservesStaticFindingsOnFailure(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, vulnerableHandler)
	for _, status := range []int{200, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		raw, err := execCLI(t, "", "security", dir, "--target", srv.URL, "--network", "allow-all", "--no-fail", "--format", "json")
		srv.Close()
		if (err != nil) != (status == 503) {
			t.Fatalf("status %d, error %v", status, err)
		}
		report := securityReport(t, raw)
		got := map[string]bool{}
		for _, f := range report.Findings {
			got[f.ID] = true
		}
		if !got["sast:go/sql-injection"] || !got["dast:unencrypted-http"] {
			t.Fatalf("combined findings missing: %s", raw)
		}
		if status == 503 && !got["dast:analysis-incomplete"] {
			t.Fatalf("partial results missing: %s", raw)
		}
	}
}

func TestDASTRejectsInvalidOptionsBeforeRequests(t *testing.T) {
	isolateHome(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	for _, flags := range [][]string{{"--fail-on", "bad"}, {"--timeout", "0s"}, {"--timeout", "-1s"}} {
		args := append([]string{"dast", srv.URL, "--network", "allow-all"}, flags...)
		if _, err := execCLI(t, "", args...); err == nil {
			t.Errorf("accepted %v", flags)
		}
	}
	if _, err := execCLI(t, "", "dast", srv.URL, "file:///etc/passwd", "--network", "allow-all"); err == nil {
		t.Fatal("accepted invalid second target")
	}
	if hits.Load() != 0 {
		t.Fatal("sent requests before validating all targets")
	}
}

func TestDASTAttemptsAllTargetsAfterFailure(t *testing.T) {
	isolateHome(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/fail" {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	raw, err := execCLI(t, "", "dast", srv.URL+"/fail", srv.URL+"/ok", "--network", "allow-all", "--no-fail", "--format", "json")
	if err == nil || hits.Load() != 2 {
		t.Fatalf("did not attempt all targets: hits %d, %v", hits.Load(), err)
	}
	if err := schemas.Validate("dast-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
	var report finding.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	subjects := map[string]bool{}
	for _, f := range report.Findings {
		subjects[f.Subject] = true
	}
	if !subjects[srv.URL+"/ok"] || !subjects[srv.URL+"/fail"] {
		t.Fatalf("results lost: %s", raw)
	}
}
