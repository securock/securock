package remediation

import (
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
	"os"
	"path/filepath"
	"strings"
)

// Patch produces a reviewable zero-context patch, without modifying the project.
func Patch(root string, f finding.Finding) (string, error) {
	if !supportedFix(f.ID) || f.Location == nil {
		return "", nil
	}
	if strings.ContainsAny(f.Location.File, "\r\n\t") {
		return "", fmt.Errorf("unsupported patch path")
	}
	base, e := filepath.EvalSymlinks(root)
	if e != nil {
		return "", e
	}
	base, e = filepath.Abs(base)
	if e != nil {
		return "", e
	}
	file, e := filepath.EvalSymlinks(filepath.Join(base, f.Location.File))
	if e != nil {
		return "", e
	}
	rel, e := filepath.Rel(base, file)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("patch target leaves project")
	}
	raw, e := os.ReadFile(file)
	if e != nil {
		return "", e
	}
	lines := strings.Split(string(raw), "\n")
	n := f.Location.Line
	if n < 1 || n > len(lines) {
		return "", fmt.Errorf("stale finding location")
	}
	// Revalidate the finding before editing. A report alone cannot establish
	// that a similarly named property belongs to a modeled TLS API.
	current, e := sast.Analyze(base)
	if e != nil {
		return "", e
	}
	locations := []*finding.Location{}
	for _, found := range current {
		if found.ID == f.ID && sameLocation(f.Location, found.Location) {
			locations = append(locations, found.Location)
		}
	}
	if f.ID == "sast:go/tls-verification-disabled" {
		// Go syntax checks retain support for reviewed package-level configurations.
		locations = []*finding.Location{f.Location}
	}
	if len(locations) == 0 {
		return "", fmt.Errorf("source no longer matches reported TLS finding")
	}
	edits, e := tlsEdits(file, raw, f.ID)
	if e != nil {
		return "", e
	}
	candidates := []edit{}
	for _, edit := range edits {
		for _, loc := range locations {
			if edit.line == loc.Line && (loc.Column == 0 || edit.column == loc.Column) {
				candidates = append(candidates, edit)
				break
			}
		}
	}
	if len(candidates) != 1 {
		return "", fmt.Errorf("source has no unambiguous supported TLS fix")
	}
	edit := candidates[0]
	line := strings.Count(string(raw[:edit.start]), "\n") + 1
	offset := strings.LastIndex(string(raw[:edit.start]), "\n") + 1
	old := lines[line-1]
	end := edit.end - offset
	begin := edit.start - offset
	if begin < 0 || end > len(old) {
		return "", fmt.Errorf("unsupported multiline value")
	}
	next := old[:begin] + edit.text + old[end:]
	suffix := ""
	if line == len(lines) && !strings.HasSuffix(string(raw), "\n") {
		suffix = "\\ No newline at end of file\n"
	}
	return fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n-%s\n%s+%s\n%s", filepath.ToSlash(rel), filepath.ToSlash(rel), line, line, old, suffix, next, suffix), nil
}
