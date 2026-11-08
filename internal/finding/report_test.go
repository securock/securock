package finding_test

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/securock/securock/internal/finding"
)

type junitDoc struct {
	Suites []struct {
		Name     string `xml:"name,attr"`
		Tests    int    `xml:"tests,attr"`
		Failures int    `xml:"failures,attr"`
		Skipped  int    `xml:"skipped,attr"`
		Cases    []struct {
			Name    string `xml:"name,attr"`
			Failure *struct {
				Type string `xml:"type,attr"`
			} `xml:"failure"`
			Skipped *struct {
				Message string `xml:"message,attr"`
			} `xml:"skipped"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func withSuppressed() finding.Report {
	r := sample()
	r.Findings[2].Suppressed = &finding.Suppression{Reason: "internal tool", Expires: "2099-01-01"}
	return r
}

func TestWriteJUnit(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.Write(&buf, withSuppressed(), "junit"); err != nil {
		t.Fatal(err)
	}
	var doc junitDoc
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid xml: %v\n%s", err, buf.String())
	}
	if len(doc.Suites) != 1 {
		t.Fatalf("suites: %d", len(doc.Suites))
	}
	s := doc.Suites[0]
	if s.Name != "securock audit" || s.Tests != 3 || s.Failures != 2 || s.Skipped != 1 {
		t.Fatalf("unexpected suite: %+v", s)
	}
	if c := s.Cases[0]; c.Failure == nil || c.Failure.Type != "critical" {
		t.Fatalf("critical finding should fail: %+v", c)
	}
	if c := s.Cases[2]; c.Skipped == nil || !strings.Contains(c.Skipped.Message, "internal tool") || c.Failure != nil {
		t.Fatalf("suppressed finding should be skipped: %+v", c)
	}
}

func TestWriteJUnitEscapesAndIsDeterministic(t *testing.T) {
	r := finding.New("audit", []finding.Finding{{ID: "x", Severity: finding.SeverityHigh, Title: `a <b> & "c"`, Subject: "npm:a@1"}})
	var one, two bytes.Buffer
	for _, b := range []*bytes.Buffer{&one, &two} {
		if err := finding.WriteJUnit(b, r); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(one.Bytes(), two.Bytes()) {
		t.Fatal("output differs between runs")
	}
	if err := xml.Unmarshal(one.Bytes(), &junitDoc{}); err != nil {
		t.Fatalf("invalid xml: %v", err)
	}
}

func TestWriteJUnitEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.WriteJUnit(&buf, finding.New("audit", nil)); err != nil {
		t.Fatal(err)
	}
	var doc junitDoc
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Suites[0].Tests != 0 || doc.Suites[0].Failures != 0 {
		t.Fatalf("unexpected suite: %+v", doc.Suites[0])
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.Write(&buf, withSuppressed(), "markdown"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"## securock audit",
		"**2 findings** (1 critical, 1 medium, 1 suppressed)",
		"| critical | `malicious-package:MAL-1` | npm:b@1 | Malicious |",
		"| low (suppressed) | `capability:network` | npm:a@1 | Uses the network |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestWriteMarkdownEscapesCells(t *testing.T) {
	r := finding.New("sast", []finding.Finding{{
		ID: "x", Severity: finding.SeverityHigh, Title: "a | b\nc",
		Location: &finding.Location{File: "a.go", Line: 7},
	}})
	var buf bytes.Buffer
	if err := finding.WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `| a.go:7 | a \| b c |`) {
		t.Fatalf("cell not escaped:\n%s", buf.String())
	}
}

func TestWriteMarkdownEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := finding.WriteMarkdown(&buf, finding.New("audit", nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings.") || strings.Contains(buf.String(), "|") {
		t.Fatalf("unexpected output:\n%s", buf.String())
	}
}
