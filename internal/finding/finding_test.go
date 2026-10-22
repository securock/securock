package finding_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/securock/securock/internal/finding"
)

func sample() finding.Report {
	return finding.New("audit", []finding.Finding{
		{ID: "missing-digest", Severity: finding.SeverityMedium, Title: "Artifact has no digest", Subject: "npm:a@1"},
		{ID: "malicious-package:MAL-1", Severity: finding.SeverityCritical, Title: "Malicious", Subject: "npm:b@1"},
		{ID: "capability:network", Severity: finding.SeverityLow, Title: "Uses the network", Subject: "npm:a@1"},
	})
}

func TestNewSortsBySeverity(t *testing.T) {
	r := sample()
	if r.Findings[0].Severity != finding.SeverityCritical || r.Findings[2].Severity != finding.SeverityLow {
		t.Fatalf("unexpected order: %+v", r.Findings)
	}
}

func TestAtLeast(t *testing.T) {
	r := sample()
	tests := []struct {
		threshold finding.Severity
		want      int
	}{
		{finding.SeverityCritical, 1},
		{finding.SeverityHigh, 1},
		{finding.SeverityMedium, 2},
		{finding.SeverityInfo, 3},
	}
	for _, tt := range tests {
		t.Run(string(tt.threshold), func(t *testing.T) {
			if got := r.AtLeast(tt.threshold); got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	if _, err := finding.ParseSeverity("High"); err != nil {
		t.Fatal(err)
	}
	if _, err := finding.ParseSeverity("urgent"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEmptyReportEncodesArray(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.WriteJSON(&buf, finding.New("audit", nil)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"findings": []`)) {
		t.Fatalf("findings should be an empty array:\n%s", buf.String())
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.WriteSARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected sarif: %s", buf.String())
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "securock audit" || len(run.Results) != 3 {
		t.Fatalf("unexpected run: %s", buf.String())
	}
	if run.Results[0].RuleID != "malicious-package" || run.Results[0].Level != "error" {
		t.Fatalf("rule id should drop the finding suffix: %+v", run.Results[0])
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules: %+v", run.Tool.Driver.Rules)
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	if err := finding.Write(&bytes.Buffer{}, sample(), "xml"); err == nil {
		t.Fatal("expected error")
	}
}
