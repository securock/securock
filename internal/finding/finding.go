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

// Count returns the number of findings at each severity.
func (r Report) Count() map[Severity]int {
	out := make(map[Severity]int, len(order))
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// AtLeast returns the number of findings at or above the threshold.
func (r Report) AtLeast(threshold Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity.Rank() >= threshold.Rank() {
			n++
		}
	}
	return n
}
