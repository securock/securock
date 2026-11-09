package finding

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type sarifInLog struct {
	Version string       `json:"version"`
	Runs    []sarifInRun `json:"runs"`
}

type sarifInRun struct {
	Tool struct {
		Driver struct {
			Name  string        `json:"name"`
			Rules []sarifInRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifInResult `json:"results"`
}

type sarifInRule struct {
	ID                   string         `json:"id"`
	ShortDescription     *sarifMessage  `json:"shortDescription"`
	Help                 *sarifMessage  `json:"help"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifInResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  *int            `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	CodeFlows  []sarifCodeFlow `json:"codeFlows"`
	Properties map[string]any  `json:"properties"`
}

// ReadSARIF converts the results of a SARIF 2.1.0 log into findings, so another tool's
// output goes through the same exceptions and --fail-on handling as securock's own.
//
// A SARIF suppression is not honored: the report is produced by a tool securock does not
// control, so accepting a finding stays a decision recorded in the exceptions file.
// A result with no usable level or security-severity is medium, never lower.
func ReadSARIF(r io.Reader) ([]Finding, error) {
	var log sarifInLog
	if err := json.NewDecoder(r).Decode(&log); err != nil {
		return nil, fmt.Errorf("read sarif: %w", err)
	}
	if log.Version != "2.1.0" {
		return nil, fmt.Errorf("read sarif: unsupported version %q, want 2.1.0", log.Version)
	}
	out := []Finding{}
	for _, run := range log.Runs {
		tool := toolSlug(run.Tool.Driver.Name)
		for _, res := range run.Results {
			out = append(out, resultFinding(tool, run, res))
		}
	}
	return out, nil
}

func resultFinding(tool string, run sarifInRun, res sarifInResult) Finding {
	rule, hasRule := findRule(run.Tool.Driver.Rules, res)
	id := res.RuleID
	if id == "" && hasRule {
		id = rule.ID
	}
	if id == "" {
		id = "unknown-rule"
	}

	f := Finding{
		ID:       "sarif:" + tool + "/" + id,
		Severity: inputSeverity(rule, hasRule, res),
		Title:    id,
	}
	text := strings.TrimSpace(res.Message.Text)
	switch {
	case hasRule && rule.ShortDescription != nil && strings.TrimSpace(rule.ShortDescription.Text) != "":
		f.Title = strings.TrimSpace(rule.ShortDescription.Text)
		f.Detail = text
	case text != "":
		f.Title, f.Detail, _ = strings.Cut(text, "\n")
		f.Detail = strings.TrimSpace(f.Detail)
	}
	if hasRule && rule.Help != nil {
		f.Remediation = strings.TrimSpace(rule.Help.Text)
	}

	if file, line, col, ok := firstPosition(res.Locations); ok {
		f.Subject = file
		if line > 0 {
			f.Location = &Location{File: file, Line: line, Column: col}
		}
	}
	if f.Location != nil && len(res.CodeFlows) > 0 && len(res.CodeFlows[0].ThreadFlows) > 0 {
		for _, tl := range res.CodeFlows[0].ThreadFlows[0].Locations {
			file, line, col, ok := firstPosition([]sarifLocation{tl.Location})
			if !ok || line < 1 {
				continue
			}
			msg := ""
			if tl.Location.Message != nil {
				msg = strings.TrimSpace(tl.Location.Message.Text)
			}
			if msg == "" {
				msg = "step"
			}
			f.Trace = append(f.Trace, Step{Location: Location{File: file, Line: line, Column: col}, Message: msg})
		}
	}
	return f
}

func findRule(rules []sarifInRule, res sarifInResult) (sarifInRule, bool) {
	if i := res.RuleIndex; i != nil && *i >= 0 && *i < len(rules) && (res.RuleID == "" || rules[*i].ID == res.RuleID) {
		return rules[*i], true
	}
	for _, r := range rules {
		if res.RuleID != "" && r.ID == res.RuleID {
			return r, true
		}
	}
	return sarifInRule{}, false
}

// inputSeverity prefers the numeric security-severity (a CVSS score, as GitHub reads it)
// over the coarser SARIF level. SARIF's own default level is warning.
func inputSeverity(rule sarifInRule, hasRule bool, res sarifInResult) Severity {
	sources := []map[string]any{res.Properties}
	if hasRule {
		sources = append(sources, rule.Properties)
	}
	for _, props := range sources {
		if score, ok := securityScore(props["security-severity"]); ok {
			switch {
			case score >= 9:
				return SeverityCritical
			case score >= 7:
				return SeverityHigh
			case score >= 4:
				return SeverityMedium
			case score > 0:
				return SeverityLow
			default:
				return SeverityInfo
			}
		}
	}
	level := strings.ToLower(res.Level)
	if level == "" && hasRule {
		level = strings.ToLower(rule.DefaultConfiguration.Level)
	}
	switch level {
	case "error":
		return SeverityHigh
	case "note":
		return SeverityLow
	case "none":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

func securityScore(v any) (float64, bool) {
	switch s := v.(type) {
	case float64:
		return s, s >= 0 && s <= 10
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return n, err == nil && n >= 0 && n <= 10
	}
	return 0, false
}

func firstPosition(locs []sarifLocation) (file string, line, col int, ok bool) {
	for _, l := range locs {
		p := l.PhysicalLocation
		if p == nil || p.ArtifactLocation.URI == "" {
			continue
		}
		file = artifactPath(p.ArtifactLocation.URI)
		if p.Region != nil {
			line, col = p.Region.StartLine, p.Region.StartColumn
		}
		return file, line, col, true
	}
	return "", 0, 0, false
}

// artifactPath turns a SARIF artifact URI into a forward-slash path, dropping a file://
// scheme and a leading "./" so the same file reads the same from any tool.
func artifactPath(uri string) string {
	p := uri
	if rest, found := strings.CutPrefix(p, "file://"); found {
		p = rest
	}
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	p = filepath.ToSlash(p)
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return p
}

// toolSlug keeps rule IDs from different tools apart: "CodeQL" becomes "codeql".
func toolSlug(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "unknown"
	}
	return strings.Join(strings.Fields(name), "-")
}

// RelativeTo rewrites absolute paths under root as paths relative to it, in place, so a
// report made on a CI runner reads the same as one made anywhere else and an exception
// written for "cmd/x.go" matches. A path outside root is left as the tool wrote it, since
// there is no relative form that would still point at the same file.
func RelativeTo(findings []Finding, root string) {
	root = strings.TrimRight(filepath.ToSlash(root), "/")
	if root == "" {
		return
	}
	rel := func(p string) string {
		if rest, ok := strings.CutPrefix(p, root+"/"); ok && rest != "" {
			return rest
		}
		return p
	}
	for i := range findings {
		f := &findings[i]
		if f.Location != nil {
			// The subject is the file for these findings; rewrite it with the location.
			if f.Subject == f.Location.File {
				f.Subject = rel(f.Subject)
			}
			loc := *f.Location
			loc.File = rel(loc.File)
			f.Location = &loc
		} else {
			f.Subject = rel(f.Subject)
		}
		if len(f.Trace) > 0 {
			trace := make([]Step, len(f.Trace))
			copy(trace, f.Trace)
			for j := range trace {
				trace[j].File = rel(trace[j].File)
			}
			f.Trace = trace
		}
	}
}
