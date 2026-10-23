package finding

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var order = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if sev.Rank() < 0 {
		return "", fmt.Errorf("unknown severity %q", s)
	}
	return sev, nil
}

// Rank orders severities from info (0) to critical (4). Unknown values rank -1.
func (s Severity) Rank() int {
	return slices.Index(order, s)
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Remediation string   `json:"remediation,omitempty"`

	// Location and Trace are set by source-code findings: where the issue is, and for
	// dataflow findings the steps from the untrusted source to the dangerous sink.
	Location *Location `json:"location,omitempty"`
	Trace    []Step    `json:"trace,omitempty"`

	// Suppressed is set when the finding has been accepted. Suppressed findings stay in
	// the report but do not count toward severity totals or --fail-on.
	Suppressed *Suppression `json:"suppressed,omitempty"`
}

// Location is a position in a source file. File is relative to the scanned directory
// and uses forward slashes; Line and Column are 1-based.
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`
}

// Step is one hop of a dataflow trace.
type Step struct {
	Location
	Message string `json:"message"`
}

type Suppression struct {
	Reason   string `json:"reason"`
	Approver string `json:"approver,omitempty"`
	Expires  string `json:"expires"`
}

type Report struct {
	Tool     string    `json:"tool"`
	Findings []Finding `json:"findings"`

	// Location is the file the findings were derived from, such as securock.lock.
	// It only anchors SARIF results and is not part of the JSON report.
	Location string `json:"-"`
}

// WithLocation returns the report with its source file set.
func (r Report) WithLocation(path string) Report {
	r.Location = path
	return r
}

func New(tool string, findings []Finding) Report {
	if findings == nil {
		findings = []Finding{}
	}
	slices.SortStableFunc(findings, func(a, b Finding) int {
		if n := cmp.Compare(b.Severity.Rank(), a.Severity.Rank()); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Subject, b.Subject); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return Report{Tool: tool, Findings: findings}
}

// Count returns the number of unsuppressed findings at each severity.
func (r Report) Count() map[Severity]int {
	out := make(map[Severity]int, len(order))
	for _, f := range r.Findings {
		if f.Suppressed == nil {
			out[f.Severity]++
		}
	}
	return out
}

// AtLeast returns the number of unsuppressed findings at or above the threshold.
func (r Report) AtLeast(threshold Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Suppressed == nil && f.Severity.Rank() >= threshold.Rank() {
			n++
		}
	}
	return n
}

// Suppressed returns the number of accepted findings.
func (r Report) Suppressed() int {
	n := 0
	for _, f := range r.Findings {
		if f.Suppressed != nil {
			n++
		}
	}
	return n
}
