package finding

import (
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strings"
)

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// WriteJUnit writes the report as JUnit XML so CI systems without SARIF support can show
// findings as failed tests. Every unsuppressed finding is a failure whatever its severity;
// use --fail-on for the exit code. An accepted finding is reported as skipped, with the
// reason, so the acceptance stays visible.
func WriteJUnit(w io.Writer, r Report) error {
	suite := junitSuite{Name: "securock " + r.Tool, Cases: []junitCase{}}
	for _, f := range r.Findings {
		c := junitCase{Name: caseName(f), ClassName: "securock." + r.Tool}
		if s := f.Suppressed; s != nil {
			c.Skipped = &junitSkipped{Message: "accepted until " + s.Expires + ": " + s.Reason}
			suite.Skipped++
		} else {
			c.Failure = &junitFailure{Message: f.Title, Type: string(f.Severity), Body: failureBody(f)}
			suite.Failures++
		}
		suite.Cases = append(suite.Cases, c)
	}
	suite.Tests = len(suite.Cases)

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(junitSuites{Suites: []junitSuite{suite}}); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func caseName(f Finding) string {
	if f.Subject == "" {
		return f.ID
	}
	return f.ID + " " + f.Subject
}

func failureBody(f Finding) string {
	var lines []string
	if l := f.Location; l != nil {
		lines = append(lines, fmt.Sprintf("at %s:%d", l.File, l.Line))
	}
	for _, s := range f.Trace {
		lines = append(lines, fmt.Sprintf("  %s:%d  %s", s.File, s.Line, s.Message))
	}
	if f.Detail != "" {
		lines = append(lines, f.Detail)
	}
	if f.Remediation != "" {
		lines = append(lines, "fix: "+f.Remediation)
	}
	return strings.Join(lines, "\n")
}

// WriteMarkdown writes a summary meant for a pull request comment or the GitHub step
// summary: a severity line, then one table row per finding.
func WriteMarkdown(w io.Writer, r Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## securock %s\n\n", r.Tool)

	counts := r.Count()
	suppressed := r.Suppressed()
	total := len(r.Findings) - suppressed
	if total == 0 && suppressed == 0 {
		b.WriteString("No findings.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	var parts []string
	for _, sev := range slices.Backward(order) {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if suppressed > 0 {
		parts = append(parts, fmt.Sprintf("%d suppressed", suppressed))
	}
	fmt.Fprintf(&b, "**%d findings**", total)
	if len(parts) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(parts, ", "))
	}
	b.WriteString("\n\n| Severity | Rule | Subject | Finding |\n| --- | --- | --- | --- |\n")
	for _, f := range r.Findings {
		sev := string(f.Severity)
		if f.Suppressed != nil {
			sev += " (suppressed)"
		}
		subject := f.Subject
		if l := f.Location; l != nil {
			subject = fmt.Sprintf("%s:%d", l.File, l.Line)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", sev, mdCell("`"+f.ID+"`"), mdCell(subject), mdCell(findingText(f)))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func findingText(f Finding) string {
	text := f.Title
	if f.Remediation != "" {
		text += ". Fix: " + f.Remediation
	}
	return text
}

// mdCell keeps a value on one table row: a pipe would split the cell and a newline would
// end the row.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", `\|`)
}
