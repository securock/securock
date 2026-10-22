package finding

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

func Write(w io.Writer, r Report, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return WriteJSON(w, r)
	case "sarif":
		return WriteSARIF(w, r)
	case "text", "":
		WriteText(w, r)
		return nil
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteText(w io.Writer, r Report) {
	counts := r.Count()
	fmt.Fprintf(w, "%d findings", len(r.Findings))
	var parts []string
	for _, sev := range slices.Backward(order) {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)

	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%s] %s  %s\n", f.Severity, f.ID, f.Title)
		if f.Subject != "" {
			fmt.Fprintf(w, "  subject  %s\n", f.Subject)
		}
		if f.Detail != "" {
			fmt.Fprintf(w, "  detail   %s\n", f.Detail)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "  fix      %s\n", f.Remediation)
		}
	}
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
}

// WriteSARIF writes the report as SARIF 2.1.0 so GitHub code scanning can ingest it.
// Findings are about packages, not source lines, so locations are logical.
func WriteSARIF(w io.Writer, r Report) error {
	driver := sarifDriver{
		Name:           "securock " + r.Tool,
		InformationURI: "https://github.com/securock/securock",
		Rules:          []sarifRule{},
	}
	results := make([]sarifResult, 0, len(r.Findings))
	seen := map[string]bool{}
	for _, f := range r.Findings {
		ruleID := ruleID(f)
		if !seen[ruleID] {
			seen[ruleID] = true
			driver.Rules = append(driver.Rules, sarifRule{ID: ruleID, ShortDescription: sarifMessage{Text: f.Title}})
		}
		text := f.Title
		if f.Detail != "" {
			text += ": " + f.Detail
		}
		res := sarifResult{RuleID: ruleID, Level: sarifLevel(f.Severity), Message: sarifMessage{Text: text}}
		if f.Subject != "" {
			res.Locations = []sarifLocation{{LogicalLocations: []sarifLogicalLocation{{Name: f.Subject}}}}
		}
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ruleID groups findings by kind: an ID like "known-vulnerability:GHSA-x" maps to "known-vulnerability".
func ruleID(f Finding) string {
	id, _, _ := strings.Cut(f.ID, ":")
	return id
}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
