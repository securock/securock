package finding_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/internal/finding"
)

func TestReadSARIFSeverity(t *testing.T) {
	tests := []struct {
		name   string
		result string
		rules  string
		want   finding.Severity
	}{
		{"error level", `"level":"error"`, `[]`, finding.SeverityHigh},
		{"warning level", `"level":"warning"`, `[]`, finding.SeverityMedium},
		{"note level", `"level":"note"`, `[]`, finding.SeverityLow},
		{"none level", `"level":"none"`, `[]`, finding.SeverityInfo},
		{"no level defaults to medium", `"x":1`, `[]`, finding.SeverityMedium},
		{"unknown level is not lowered", `"level":"bogus"`, `[]`, finding.SeverityMedium},
		{"rule default level", `"x":1`, `[{"id":"r","defaultConfiguration":{"level":"error"}}]`, finding.SeverityHigh},
		{"result level beats rule default", `"level":"note"`, `[{"id":"r","defaultConfiguration":{"level":"error"}}]`, finding.SeverityLow},
		{"security severity critical", `"level":"note"`, `[{"id":"r","properties":{"security-severity":"9.8"}}]`, finding.SeverityCritical},
		{"security severity high", `"level":"note"`, `[{"id":"r","properties":{"security-severity":7.0}}]`, finding.SeverityHigh},
		{"security severity medium", `"level":"error"`, `[{"id":"r","properties":{"security-severity":"4.0"}}]`, finding.SeverityMedium},
		{"security severity low", `"level":"error"`, `[{"id":"r","properties":{"security-severity":"0.1"}}]`, finding.SeverityLow},
		{"out of range score is ignored", `"level":"error"`, `[{"id":"r","properties":{"security-severity":"11"}}]`, finding.SeverityHigh},
		{"result score beats rule score", `"properties":{"security-severity":"9.5"}`, `[{"id":"r","properties":{"security-severity":"1.0"}}]`, finding.SeverityCritical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":` + tt.rules + `}},` +
				`"results":[{"ruleId":"r",` + tt.result + `,"message":{"text":"m"}}]}]}`
			got, err := finding.ReadSARIF(strings.NewReader(log))
			if err != nil || len(got) != 1 {
				t.Fatalf("err = %v, findings = %+v", err, got)
			}
			if got[0].Severity != tt.want {
				t.Fatalf("severity = %s, want %s", got[0].Severity, tt.want)
			}
		})
	}
}

func TestReadSARIFFields(t *testing.T) {
	log := `{"version":"2.1.0","runs":[{
	  "tool":{"driver":{"name":"Semgrep OSS","rules":[
	    {"id":"a.rule","shortDescription":{"text":"Short title"},"help":{"text":"Use the safe API"}}]}},
	  "results":[
	    {"ruleId":"a.rule","ruleIndex":0,"level":"error","message":{"text":"long explanation"},
	     "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file://./src/a%20b.go"},"region":{"startLine":7,"startColumn":3}}}],
	     "codeFlows":[{"threadFlows":[{"locations":[
	       {"location":{"message":{"text":"source"},"physicalLocation":{"artifactLocation":{"uri":"src/a.go"},"region":{"startLine":2}}}},
	       {"location":{"physicalLocation":{"artifactLocation":{"uri":"src/a.go"},"region":{"startLine":7}}}}]}]}],
	     "suppressions":[{"kind":"inSource","status":"accepted"}]},
	    {"message":{"text":"first line\nsecond line"},
	     "locations":[{"physicalLocation":{"artifactLocation":{"uri":"cfg/app.yaml"}}}]}
	  ]}]}`
	got, err := finding.ReadSARIF(strings.NewReader(log))
	if err != nil || len(got) != 2 {
		t.Fatalf("err = %v, findings = %+v", err, got)
	}

	a := got[0]
	if a.ID != "sarif:semgrep-oss/a.rule" || a.Title != "Short title" || a.Detail != "long explanation" || a.Remediation != "Use the safe API" {
		t.Errorf("fields: %+v", a)
	}
	if a.Subject != "src/a b.go" || a.Location == nil || *a.Location != (finding.Location{File: "src/a b.go", Line: 7, Column: 3}) {
		t.Errorf("location: subject %q, %+v", a.Subject, a.Location)
	}
	if len(a.Trace) != 2 || a.Trace[0].Message != "source" || a.Trace[0].Line != 2 || a.Trace[1].Message != "step" {
		t.Errorf("trace: %+v", a.Trace)
	}
	if a.Suppressed != nil {
		t.Errorf("a suppression inside the sarif file must not be honored: %+v", a.Suppressed)
	}

	b := got[1]
	if b.ID != "sarif:semgrep-oss/unknown-rule" || b.Title != "first line" || b.Detail != "second line" {
		t.Errorf("rule-less result: %+v", b)
	}
	if b.Subject != "cfg/app.yaml" || b.Location != nil {
		t.Errorf("a result without a region has a subject but no line: %+v", b)
	}
}

func TestReadSARIFRejects(t *testing.T) {
	tests := map[string]string{
		"not json":      `nope`,
		"wrong version": `{"version":"2.0.0","runs":[]}`,
		"no version":    `{"runs":[]}`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := finding.ReadSARIF(strings.NewReader(in)); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestReadSARIFEmpty(t *testing.T) {
	got, err := finding.ReadSARIF(strings.NewReader(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}}}]}`))
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("want an empty, non-nil list: %+v, %v", got, err)
	}
}
