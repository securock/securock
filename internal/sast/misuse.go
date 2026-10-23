package sast

import (
	"fmt"
	"go/token"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// A misuse is an unsafe call that needs no untrusted data to be wrong: a weak hash, a
// disabled certificate check, debug mode left on. The rule is a call to a known function
// whose constant arguments select the unsafe form.

type misuse struct {
	rule   rule
	detail string
	// args maps an argument index to the values it must carry for the call to be unsafe.
	// A value matches when the constant argument contains it (lower-cased), or equals it
	// when it starts with "=". Every listed index must match.
	args map[int][]string
	// kw maps a keyword argument to the value that makes the call unsafe.
	kw map[string]string
	// bare reports the call whatever its arguments are.
	bare bool
	// noKw makes the call unsafe only when this keyword argument is absent:
	// tarfile.extractall without filter=.
	noKw string
	// recv limits a method misuse to receivers rooted at one of these variable names.
	recv []string
}

// assignMisuse flags assigning one of the values to a property: verify_mode =
// VERIFY_NONE, process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0".
type assignMisuse struct {
	rule   rule
	detail string
	vals   []string
	// file limits the check to paths containing this text: DEBUG = True in settings.py.
	file string
}

var (
	ruleDebug = rule{"sast:go/debug-enabled", "CWE-489", "Debug mode enabled",
		"Never run with debug on in production; read the setting from the environment and default it to off.", finding.SeverityMedium}
	ruleJWT = rule{"sast:go/jwt-unverified", "CWE-347", "Token signature is not verified",
		"Verify the signature with a fixed, expected algorithm and key before trusting any claim.", finding.SeverityHigh}
	ruleMassAssign = rule{"sast:go/mass-assignment", "CWE-915", "All request parameters are permitted",
		"Permit an explicit list of attributes instead of everything.", finding.SeverityMedium}
	ruleTempFile = rule{"sast:go/insecure-temp-file", "CWE-377", "Predictable temporary file",
		"Create temporary files with mkstemp or NamedTemporaryFile, which pick an unpredictable name atomically.", finding.SeverityLow}
	ruleCookie = rule{"sast:go/insecure-cookie", "CWE-614", "Cookie is sent without the Secure or HttpOnly flag",
		"Set Secure and HttpOnly on session and authentication cookies.", finding.SeverityMedium}
	ruleXXE = rule{"sast:go/xxe", "CWE-611", "XML external entities are enabled",
		"Disable DTDs and external entity resolution in the XML parser.", finding.SeverityHigh}
	ruleCSRF = rule{"sast:go/csrf-disabled", "CWE-352", "CSRF protection is switched off",
		"Keep CSRF protection on for state-changing requests, and exempt only endpoints that use another proof of origin.", finding.SeverityMedium}
	ruleWorldWritable = rule{"sast:go/world-writable", "CWE-732", "File is made world-writable",
		"Use the narrowest mode that works, such as 0600 for files and 0750 for directories.", finding.SeverityMedium}
	ruleZipSlip = rule{"sast:go/zip-slip", "CWE-22", "Archive extraction can write outside the target directory",
		"Resolve each entry against the destination and reject any that leaves it, or extract with a filter that does (tarfile filter=\"data\").", finding.SeverityHigh}
	ruleExtract = rule{"sast:go/variable-extraction", "CWE-621", "Request data is imported into the variable scope",
		"Read the specific parameters you need instead of extract()ing the request.", finding.SeverityHigh}
)

func (r *irRun) rulesFor(lang string, m misuse) rule {
	ru := m.rule
	ru.id = strings.Replace(ru.id, "go/", lang+"/", 1)
	return ru
}

// constText is the lower-cased value of a literal or name argument, for matching.
func constText(e *expr) (string, bool) {
	switch e.kind {
	case exprStr, exprNum:
		return strings.ToLower(e.str), true
	case exprName:
		return strings.ToLower(e.name), true
	case exprMember:
		return strings.ToLower(e.name), true
	}
	return "", false
}

func matchesName(have string, names []string) bool {
	for _, n := range names {
		if have == n {
			return true
		}
	}
	return false
}

func matchesAny(have string, want []string) bool {
	for _, w := range want {
		if exact, ok := strings.CutPrefix(w, "="); ok {
			if have == exact {
				return true
			}
		} else if strings.Contains(have, w) {
			return true
		}
	}
	return false
}

func (m misuse) matches(c *expr) bool {
	if len(m.recv) > 0 {
		if c.x == nil || c.x.kind != exprMember || !matchesName(rootName(c.x.x), m.recv) {
			return false
		}
	}
	if m.noKw != "" {
		for _, k := range c.kw {
			if k == m.noKw {
				return false
			}
		}
		return true
	}
	if m.bare {
		for _, k := range c.kw {
			if k == "usedforsecurity" {
				return false
			}
		}
		return true
	}
	for i, want := range m.args {
		if i >= len(c.args) {
			return false
		}
		have, ok := constText(c.args[i])
		if !ok || !matchesAny(have, want) {
			return false
		}
	}
	for k, v := range m.kw {
		found := false
		for i, name := range c.kw {
			if name == k {
				if have, ok := constText(c.args[i]); ok && have == v {
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	return len(m.args) > 0 || len(m.kw) > 0
}

// checkMisuse reports the unsafe forms of a call to qname (or to a method called field).
func (r *irRun) checkMisuse(c *expr, qname, field string) {
	for _, key := range []string{qname, "?." + field} {
		if key == "?." {
			continue
		}
		for _, m := range r.spec.misuse[key] {
			if m.matches(c) {
				r.reportMisuse(c.pos, r.rulesFor(r.spec.name, m), m.detail)
			}
		}
	}
}

func (r *irRun) reportMisuse(pos token.Pos, ru rule, detail string) {
	l := r.loc(pos)
	key := fmt.Sprintf("%s|%s|%d|%d", ru.id, l.File, l.Line, l.Column)
	if _, dup := r.found[key]; dup {
		return
	}
	r.found[key] = finding.Finding{
		ID:          ru.id,
		Severity:    ru.sev,
		Title:       ru.title + " (" + ru.cwe + ")",
		Detail:      detail,
		Subject:     fmt.Sprintf("%s#%s", l.File, r.ctx.label),
		Remediation: ru.fix,
		Location:    l,
	}
}

func (r *irRun) checkAssignMisuse(lhs, rhs *expr) {
	if (lhs.kind != exprMember && lhs.kind != exprName) || rhs == nil {
		return
	}
	am, ok := r.spec.assignMisuse[lhs.name]
	if !ok || (am.file != "" && !strings.Contains(strings.ToLower(r.mod.path), am.file)) {
		return
	}
	have, ok := constText(rhs)
	if !ok || !matchesAny(have, am.vals) {
		return
	}
	ru := am.rule
	ru.id = strings.Replace(ru.id, "go/", r.spec.name+"/", 1)
	r.reportMisuse(lhs.pos, ru, am.detail)
}
