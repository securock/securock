package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/securock/securock/internal/finding"
)

func Read(r io.Reader) (finding.Report, error) {
	var report finding.Report
	raw, err := io.ReadAll(io.LimitReader(r, 32<<20+1))
	if err != nil || len(raw) > 32<<20 {
		return report, fmt.Errorf("report exceeds limit or cannot be read")
	}
	if json.Unmarshal(raw, &report) != nil || report.Tool == "" || report.Findings == nil {
		return report, fmt.Errorf("expected a Securock JSON finding report")
	}
	for _, f := range report.Findings {
		if f.ID == "" || f.Title == "" || f.Severity.Rank() < 0 {
			return report, fmt.Errorf("invalid finding in report")
		}
	}
	return report, nil
}

// Key excludes positions: moving a function does not make its findings new.
func Key(f finding.Finding) string {
	file := ""
	if f.Location != nil {
		file = f.Location.File
	}
	raw, _ := json.Marshal([]string{f.ID, f.Subject, file})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func Incomplete(f finding.Finding) bool {
	return strings.Contains(f.ID, "incomplete") || strings.Contains(f.ID, "unchecked") || strings.Contains(f.ID, "unavailable") || strings.Contains(f.ID, "snapshot-scope")
}

// New keeps multiset occurrences and severity escalations. Missing findings are
// unobserved, never asserted resolved without evidence of matching scan coverage.
func New(old, current finding.Report) finding.Report {
	counts := map[string]int{}
	for _, f := range old.Findings {
		if f.Suppressed == nil && !Incomplete(f) {
			counts[Key(f)+string(f.Severity)]++
		}
	}
	var out []finding.Finding
	for _, f := range current.Findings {
		key := Key(f) + string(f.Severity)
		if !Incomplete(f) && counts[key] > 0 {
			counts[key]--
			continue
		}
		out = append(out, f)
	}
	return finding.New(current.Tool, out)
}
