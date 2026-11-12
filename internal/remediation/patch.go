package remediation

import (
	"fmt"
	"github.com/securock/securock/internal/finding"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Patch produces a reviewable zero-context patch, without modifying the project.
func Patch(root string, f finding.Finding) (string, error) {
	if f.ID != "sast:go/tls-verification-disabled" || f.Location == nil {
		return "", nil
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
	re := regexp.MustCompile(`\bInsecureSkipVerify\s*:\s*true\b`)
	old := lines[n-1]
	if len(re.FindAllStringIndex(old, -1)) != 1 {
		return "", fmt.Errorf("source no longer matches supported TLS fix")
	}
	next := re.ReplaceAllString(old, "InsecureSkipVerify: false")
	return fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n-%s\n+%s\n", filepath.ToSlash(rel), filepath.ToSlash(rel), n, n, old, next), nil
}
