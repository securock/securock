package chain

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Count returns the number of chains at each severity, confirmed and possible alike.
func (r Report) Count() map[finding.Severity]int {
	out := make(map[finding.Severity]int)
	for _, c := range r.Chains {
		out[c.Severity]++
	}
	return out
}

// AtLeast returns the number of confirmed chains at or above the threshold. Possible
// chains name a risk that was not proven, so they never fail a build.
func (r Report) AtLeast(threshold finding.Severity) int {
	n := 0
	for _, c := range r.Chains {
		if c.Status == Confirmed && c.Severity.Rank() >= threshold.Rank() {
			n++
		}
	}
	return n
}

// Write renders the report as text, JSON or SARIF.
func Write(w io.Writer, r Report, format string) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "sarif":
		return finding.WriteSARIF(w, sarifReport(r))
	case "text", "":
		WriteText(w, r)
		return nil
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func WriteText(w io.Writer, r Report) {
	confirmed, possible := 0, 0
	for _, c := range r.Chains {
		if c.Status == Confirmed {
			confirmed++
		} else {
			possible++
		}
	}
	fmt.Fprintf(w, "%d chains", len(r.Chains))
	var parts []string
	if confirmed > 0 {
		parts = append(parts, fmt.Sprintf("%d confirmed", confirmed))
	}
	if possible > 0 {
		parts = append(parts, fmt.Sprintf("%d possible", possible))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)

	for _, c := range r.Chains {
		fmt.Fprintf(w, "\n[%s, %s] %s\n", c.Severity, c.Status, c.ID)
		fmt.Fprintf(w, "  summary  %s\n", c.Summary)
		for _, n := range c.Nodes {
			fmt.Fprintf(w, "  %-8s %s", n.Stage, n.FindingID)
			if n.Location != nil {
				fmt.Fprintf(w, "  at %s:%d", n.Location.File, n.Location.Line)
			}
			if n.Detail != "" {
				fmt.Fprintf(w, "  %s", n.Detail)
			}
			fmt.Fprintln(w)
		}
		for _, l := range c.Links {
			fmt.Fprintf(w, "  link     %s → %s (%s): %s\n",
				c.Nodes[l.From].Stage, c.Nodes[l.To].Stage, l.Status, l.Reason)
		}
	}
}

// sarifReport turns chains into findings so code scanning shows each chain as one
// result with its stages as the code flow. Chains keep their order: the report is
// already sorted, and re-sorting by the finding package would scramble it.
func sarifReport(r Report) finding.Report {
	fs := make([]finding.Finding, 0, len(r.Chains))
	for _, c := range r.Chains {
		var subjects []string
		var trace []finding.Step
		var loc *finding.Location
		for _, n := range c.Nodes {
			subjects = append(subjects, n.FindingID)
			msg := string(n.Stage) + ": " + n.FindingID
			if n.Detail != "" {
				msg += " - " + n.Detail
			}
			if n.Location != nil {
				if loc == nil {
					loc = n.Location
				}
				trace = append(trace, finding.Step{Location: *n.Location, Message: msg})
			}
		}
		fs = append(fs, finding.Finding{
			ID:       "chain",
			Severity: c.Severity,
			Title:    "Attack chain",
			Detail:   "[" + c.Status + "] " + c.Summary,
			Subject:  strings.Join(subjects, " -> "),
			Location: loc,
			Trace:    trace,
		})
	}
	return finding.Report{Tool: "chain", Findings: fs}
}
