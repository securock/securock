package sast

import (
	"go/token"
	"regexp"

	"github.com/securock/securock/internal/finding"
)

var (
	ruleWeakAllowlist = rule{"sast:go/weak-allowlist", "CWE-601", "URL allowlist is matched by substring or prefix",
		"Parse the URL and compare its scheme and host exactly with the allowed ones; a substring or prefix test accepts https://allowed.example.evil.com and https://evil.com/?https://allowed.example.",
		finding.SeverityMedium}
	ruleDirListing = rule{"sast:go/directory-listing", "CWE-548", "Directory listing is served",
		"Serve named files only; do not expose a directory index.", finding.SeverityMedium}
)

var (
	urlish   = regexp.MustCompile(`(?i)(url|uri|redirect|target|dest|href|origin|next|returnto|return_to)`)
	allowish = regexp.MustCompile(`(?i)(allow|whitelist|trusted|permitted|approved)`)
)

// weakAllow builds the check for "url.includes(allowedUrl)" and its siblings: comparing a
// URL with an allowlist by substring or prefix. It returns nil for any other membership test.
func (l *lowering) weakAllow(pos token.Pos, subject, listItem string) *expr {
	if !urlish.MatchString(subject) || !allowish.MatchString(listItem) {
		return nil
	}
	call := &expr{kind: exprCall, pos: pos, x: &expr{kind: exprName, pos: pos, name: "weakAllowlist"}}
	return call
}

// withWeakAllow keeps a membership test as it is and adds the weak-allowlist check beside it.
func withWeakAllow(in *expr, weak *expr) *expr {
	if weak == nil {
		return in
	}
	return &expr{kind: exprAnd, pos: in.pos, args: []*expr{in, weak}}
}
