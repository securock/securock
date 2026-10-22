package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
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
	ID                   string        `json:"id"`
	ShortDescription     sarifMessage  `json:"shortDescription"`
	Help                 *sarifMessage `json:"help,omitempty"`
	DefaultConfiguration sarifConfig   `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          sarifProperties   `json:"properties"`
}

type sarifProperties struct {
	Severity    Severity `json:"severity"`
	Subject     string   `json:"subject,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
}

// WriteSARIF writes the report as SARIF 2.1.0 so GitHub code scanning can ingest it.
// Findings are about packages, not source lines: each result points at the report's
// source file (when known) and names the package as a logical location.
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
			rule := sarifRule{
				ID:                   ruleID,
				ShortDescription:     sarifMessage{Text: f.Title},
				DefaultConfiguration: sarifConfig{Level: sarifLevel(f.Severity)},
			}
			if f.Remediation != "" {
				rule.Help = &sarifMessage{Text: f.Remediation}
			}
			driver.Rules = append(driver.Rules, rule)
		}
		text := f.Title
		if f.Detail != "" {
			text += ": " + f.Detail
		}
		res := sarifResult{
			RuleID:              ruleID,
			Level:               sarifLevel(f.Severity),
			Message:             sarifMessage{Text: text},
			PartialFingerprints: map[string]string{"securock/v1": fingerprint(f)},
			Properties:          sarifProperties{Severity: f.Severity, Subject: f.Subject, Remediation: f.Remediation},
		}
		if loc, ok := sarifLocationOf(r.Location, f.Subject); ok {
			res.Locations = []sarifLocation{loc}
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

func sarifLocationOf(file, subject string) (sarifLocation, bool) {
	var loc sarifLocation
	if file != "" {
		loc.PhysicalLocation = &sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(file)}}
	}
	if subject != "" {
		loc.LogicalLocations = []sarifLogicalLocation{{Name: subject}}
	}
	return loc, loc.PhysicalLocation != nil || len(loc.LogicalLocations) > 0
}

// fingerprint is stable across runs so code scanning can track the same finding over time.
func fingerprint(f Finding) string {
	sum := sha256.Sum256([]byte(f.ID + "\x00" + f.Subject))
	return hex.EncodeToString(sum[:16])
}

// instanceRules carry a per-finding suffix, such as an advisory ID, that is not part of the rule.
var instanceRules = []string{"known-vulnerability", "malicious-package"}

// ruleID groups findings by kind: "known-vulnerability:GHSA-x" maps to "known-vulnerability",
// while "capability:network" stays distinct because the suffix names the rule itself.
func ruleID(f Finding) string {
	kind, _, _ := strings.Cut(f.ID, ":")
	if slices.Contains(instanceRules, kind) {
		return kind
	}
	return f.ID
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
