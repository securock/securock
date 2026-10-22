// Package exceptions loads, edits, and applies the accepted-findings file.
package exceptions

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/securock/securock/internal/decode"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/exceptions"
	"gopkg.in/yaml.v3"
)

const maxFileBytes = 1 << 20

const header = "# Findings accepted for a stated reason, each until a date. Managed by securock accept.\n"

// Path returns the exceptions file for a project: the override when given (relative
// overrides resolve against the project root), otherwise .securock/exceptions.yaml.
func Path(root, override string) string {
	switch {
	case override == "":
		return filepath.Join(root, filepath.FromSlash(exceptions.DefaultPath))
	case filepath.IsAbs(override):
		return override
	default:
		return filepath.Join(root, override)
	}
}

// Load reads the exceptions file. A missing file is an empty document, not an error,
// because most projects have no exceptions.
func Load(path string) (exceptions.Document, error) {
	raw, err := core.ReadFileLimit(path, maxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return exceptions.Document{Version: exceptions.SchemaVersion}, nil
	}
	if err != nil {
		return exceptions.Document{}, err
	}
	var doc exceptions.Document
	if err := decode.YAML(raw, &doc); err != nil {
		return exceptions.Document{}, fmt.Errorf("parse exceptions: %w", err)
	}
	if err := exceptions.Validate(doc); err != nil {
		return exceptions.Document{}, fmt.Errorf("validate exceptions: %w", err)
	}
	return doc, nil
}

// Save writes the document in canonical order, creating the directory if needed.
func Save(path string, doc exceptions.Document) error {
	doc = exceptions.Canonicalize(doc)
	if err := exceptions.Validate(doc); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// Upsert adds an exception, replacing one that covers the same finding and package.
// It reports whether an existing exception was renewed.
func Upsert(doc exceptions.Document, e exceptions.Exception) (exceptions.Document, bool) {
	doc.Version = exceptions.SchemaVersion
	out := make([]exceptions.Exception, 0, len(doc.Exceptions)+1)
	renewed := false
	for _, existing := range doc.Exceptions {
		if existing.Same(e) {
			renewed = true
			continue
		}
		out = append(out, existing)
	}
	doc.Exceptions = append(out, e)
	return doc, renewed
}

// Remove drops the exception that covers the same finding and package.
func Remove(doc exceptions.Document, id, subject string) (exceptions.Document, bool) {
	target := exceptions.Exception{ID: id, Subject: subject}
	out := make([]exceptions.Exception, 0, len(doc.Exceptions))
	removed := false
	for _, existing := range doc.Exceptions {
		if existing.Same(target) {
			removed = true
			continue
		}
		out = append(out, existing)
	}
	doc.Exceptions = out
	return doc, removed
}

// Apply suppresses findings covered by an active exception. A finding whose only
// matching exceptions have expired stays visible, and each such exception adds an
// exception-expired finding so the lapse is not silent.
func Apply(r finding.Report, doc exceptions.Document, now time.Time) finding.Report {
	if len(doc.Exceptions) == 0 {
		return r
	}
	findings := append([]finding.Finding(nil), r.Findings...)
	lapsed := map[int]bool{}
	for i, f := range findings {
		active := -1
		for j, e := range doc.Exceptions {
			if !e.Matches(f.ID, f.Subject) {
				continue
			}
			if e.Expired(now) {
				lapsed[j] = true
				continue
			}
			active = j
			break
		}
		if active >= 0 {
			e := doc.Exceptions[active]
			findings[i].Suppressed = &finding.Suppression{Reason: e.Reason, Approver: e.Approver, Expires: e.Expires}
		}
	}
	for j, e := range doc.Exceptions {
		if !lapsed[j] || !hasUnsuppressed(findings, e) {
			continue
		}
		findings = append(findings, ExpiredFinding(e))
	}
	// Keep the rest of the report as it was; only the findings change.
	r.Findings = finding.New(r.Tool, findings).Findings
	return r
}

func hasUnsuppressed(findings []finding.Finding, e exceptions.Exception) bool {
	for _, f := range findings {
		if f.Suppressed == nil && e.Matches(f.ID, f.Subject) {
			return true
		}
	}
	return false
}

// ExpiredFinding describes a lapsed exception.
func ExpiredFinding(e exceptions.Exception) finding.Finding {
	return finding.Finding{
		ID:          "exception-expired",
		Severity:    finding.SeverityMedium,
		Title:       "An accepted finding has expired",
		Detail:      fmt.Sprintf("%s expired on %s (accepted because: %s)", e.ID, e.Expires, e.Reason),
		Subject:     e.Subject,
		Remediation: "Fix the finding, or renew it with securock accept.",
	}
}
