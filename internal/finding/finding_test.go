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

type sarifDoc struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID                   string `json:"id"`
					ShortDescription     struct{ Text string }
					Help                 *struct{ Text string }
					DefaultConfiguration struct{ Level string }
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID              string            `json:"ruleId"`
			Level               string            `json:"level"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          struct {
				Severity    string `json:"severity"`
				Subject     string `json:"subject"`
				Remediation string `json:"remediation"`
			} `json:"properties"`
			Locations []struct {
				PhysicalLocation *struct {
					ArtifactLocation struct{ URI string } `json:"artifactLocation"`
				} `json:"physicalLocation"`
				LogicalLocations []struct{ Name string } `json:"logicalLocations"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, r finding.Report) sarifDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := finding.WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	var log sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected sarif: %s", buf.String())
	}
	return log
}

func TestWriteSARIF(t *testing.T) {
	log := decodeSARIF(t, sample().WithLocation("securock.lock"))
	run := log.Runs[0]
	if run.Tool.Driver.Name != "securock audit" || len(run.Results) != 3 {
		t.Fatalf("unexpected run: %+v", run)
	}
	if run.Results[0].RuleID != "malicious-package" || run.Results[0].Level != "error" {
		t.Fatalf("rule id should drop the advisory suffix: %+v", run.Results[0])
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules: %+v", run.Tool.Driver.Rules)
	}
	for _, res := range run.Results {
		if res.PartialFingerprints["securock/v1"] == "" {
			t.Fatalf("missing fingerprint: %+v", res)
		}
		if res.Properties.Severity == "" || res.Properties.Subject == "" {
			t.Fatalf("missing properties: %+v", res)
		}
		loc := res.Locations[0]
		if loc.PhysicalLocation == nil || loc.PhysicalLocation.ArtifactLocation.URI != "securock.lock" {
			t.Fatalf("missing physical location: %+v", loc)
		}
		if len(loc.LogicalLocations) != 1 || loc.LogicalLocations[0].Name != res.Properties.Subject {
			t.Fatalf("missing logical location: %+v", loc)
		}
	}
}

func TestSARIFRulesKeepDistinctKinds(t *testing.T) {
	r := finding.New("audit", []finding.Finding{
		{ID: "capability:network", Severity: finding.SeverityLow, Title: "Uses the network", Subject: "npm:a@1", Remediation: "Review it."},
		{ID: "capability:shell", Severity: finding.SeverityMedium, Title: "Executes shell commands", Subject: "npm:a@1"},
		{ID: "known-vulnerability:GHSA-1", Severity: finding.SeverityHigh, Title: "Known vulnerability", Subject: "npm:a@1"},
		{ID: "known-vulnerability:GHSA-2", Severity: finding.SeverityHigh, Title: "Known vulnerability", Subject: "npm:a@1"},
	})
	rules := decodeSARIF(t, r).Runs[0].Tool.Driver.Rules
	got := map[string]string{}
	for _, rule := range rules {
		got[rule.ID] = rule.ShortDescription.Text
	}
	want := map[string]string{
		"capability:network":  "Uses the network",
		"capability:shell":    "Executes shell commands",
		"known-vulnerability": "Known vulnerability",
	}
	if len(got) != len(want) {
		t.Fatalf("rules: %v", got)
	}
	for id, title := range want {
		if got[id] != title {
			t.Fatalf("rule %s: got %q, want %q", id, got[id], title)
		}
	}
	for _, rule := range rules {
		if rule.ID == "capability:network" && (rule.Help == nil || rule.Help.Text != "Review it.") {
			t.Fatalf("remediation should become rule help: %+v", rule)
		}
	}
}

func TestSARIFFingerprintIsStableAndDistinct(t *testing.T) {
	a := decodeSARIF(t, sample()).Runs[0].Results
	b := decodeSARIF(t, sample()).Runs[0].Results
	seen := map[string]bool{}
	for i := range a {
		fp := a[i].PartialFingerprints["securock/v1"]
		if fp != b[i].PartialFingerprints["securock/v1"] {
			t.Fatal("fingerprint changed between runs")
		}
		if seen[fp] {
			t.Fatalf("duplicate fingerprint %s", fp)
		}
		seen[fp] = true
	}
}

func TestSARIFWithoutLocationOrSubject(t *testing.T) {
	r := finding.New("doctor", []finding.Finding{{ID: "policy-changed", Severity: finding.SeverityHigh, Title: "Policy changed"}})
	if got := decodeSARIF(t, r).Runs[0].Results[0].Locations; len(got) != 0 {
		t.Fatalf("expected no locations: %+v", got)
	}
}

func TestLocationIsNotInJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.WriteJSON(&buf, sample().WithLocation("securock.lock")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("securock.lock")) {
		t.Fatalf("location leaked into json:\n%s", buf.String())
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	if err := finding.Write(&bytes.Buffer{}, sample(), "xml"); err == nil {
		t.Fatal("expected error")
	}
}

func suppressedSample() finding.Report {
	r := sample()
	for i := range r.Findings {
		if r.Findings[i].ID == "malicious-package:MAL-1" {
			r.Findings[i].Suppressed = &finding.Suppression{Reason: "false positive", Approver: "alice", Expires: "2026-12-31"}
		}
	}
	return r
}

func TestSuppressedFindingsDoNotCount(t *testing.T) {
	r := suppressedSample()
	if got := r.AtLeast(finding.SeverityCritical); got != 0 {
		t.Fatalf("AtLeast critical = %d, want 0", got)
	}
	if got := r.AtLeast(finding.SeverityInfo); got != 2 {
		t.Fatalf("AtLeast info = %d, want 2", got)
	}
	if got := r.Count()[finding.SeverityCritical]; got != 0 {
		t.Fatalf("Count critical = %d, want 0", got)
	}
	if got := r.Suppressed(); got != 1 {
		t.Fatalf("Suppressed = %d, want 1", got)
	}
}

func TestSuppressedFindingsInTextAndJSON(t *testing.T) {
	var text bytes.Buffer
	finding.WriteText(&text, suppressedSample())
	for _, want := range []string{"2 findings (", "1 suppressed", "[critical, suppressed]", "accepted until 2026-12-31: false positive (alice)"} {
		if !bytes.Contains(text.Bytes(), []byte(want)) {
			t.Fatalf("text output missing %q:\n%s", want, text.String())
		}
	}

	var js bytes.Buffer
	if err := finding.WriteJSON(&js, suppressedSample()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(js.Bytes(), []byte(`"suppressed": {`)) || !bytes.Contains(js.Bytes(), []byte(`"reason": "false positive"`)) {
		t.Fatalf("json output missing the suppression:\n%s", js.String())
	}
	if bytes.Count(js.Bytes(), []byte(`"suppressed"`)) != 1 {
		t.Fatalf("only the accepted finding should carry a suppression:\n%s", js.String())
	}
}

func TestSARIFSuppressions(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.WriteSARIF(&buf, suppressedSample()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	var withSuppression int
	for _, res := range log.Runs[0].Results {
		if len(res.Suppressions) == 0 {
			continue
		}
		withSuppression++
		s := res.Suppressions[0]
		if res.RuleID != "malicious-package" || s.Kind != "external" || s.Status != "accepted" || s.Justification != "false positive (accepted until 2026-12-31 by alice)" {
			t.Fatalf("suppression: %+v on %s", s, res.RuleID)
		}
	}
	if withSuppression != 1 {
		t.Fatalf("results with suppressions = %d, want 1", withSuppression)
	}
}
