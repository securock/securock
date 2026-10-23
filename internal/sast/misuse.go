package sast

import (
	"fmt"
	"go/token"
	"regexp"
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
	// argc limits the misuse to calls with exactly this many arguments: ldap_bind($conn)
	// binds anonymously.
	argc int
	// missingKw makes the call unsafe when any of these keyword arguments is absent or
	// false: set_cookie(name, value) without secure=True.
	missingKw []string
	// argRe maps an argument index to a pattern its variable name must match:
	// md5($password) matters, md5($cacheKey) does not.
	argRe map[int]*regexp.Regexp
	// recvCall requires the receiver to be the result of a call with this name:
	// http.csrf().disable() and authorize.anyRequest().permitAll().
	recvCall string
	// literal requires these arguments to be string literals (a signing key written in
	// the source rather than read from configuration).
	literal map[int]bool
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
	// skip excludes paths containing any of these: development.rb is meant to show errors.
	skip []string
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
	ruleEscape = rule{"sast:go/template-autoescape-disabled", "CWE-79", "Template auto-escaping is turned off",
		"Leave auto-escaping on and mark individual trusted values as safe instead.", finding.SeverityMedium}
	ruleHTTPS = rule{"sast:go/https-not-enforced", "CWE-319", "HTTPS is not enforced",
		"Force TLS (force_ssl, HSTS, a redirect to https) so credentials and cookies never travel in clear text.", finding.SeverityMedium}
	ruleCipherMisuse = rule{"sast:go/weak-crypto", "CWE-327", "Weak cryptographic primitive",
		"Use AES-GCM or ChaCha20-Poly1305 with a random nonce, and SHA-256 or better for hashing.", finding.SeverityMedium}
	ruleDeserCfg = rule{"sast:go/insecure-deserialization", "CWE-502", "Insecure deserialization is configured",
		"Use a data-only serializer such as JSON.", finding.SeverityHigh}
	rulePermitAll = rule{"sast:go/permit-all", "CWE-862", "Every request is permitted without authentication",
		"Require authentication by default and open up only the specific public paths.", finding.SeverityHigh}
	ruleHardKey = rule{"sast:go/hardcoded-signing-key", "CWE-321", "Token signing key is written in the source",
		"Load the key from a secret store or the environment, rotate the exposed one, and use a key of at least 256 random bits.", finding.SeverityHigh}
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

func (m misuse) matches(c *expr, constText func(*expr) (string, bool)) bool {
	if m.recvCall != "" {
		if c.x == nil || c.x.kind != exprMember || c.x.x == nil || c.x.x.kind != exprCall || c.x.x.x == nil || lastName(c.x.x.x) != m.recvCall {
			return false
		}
	}
	for i := range m.literal {
		if i >= len(c.args) || c.args[i].kind != exprStr || len(c.args[i].str) < 4 {
			return false
		}
	}
	if len(m.literal) > 0 && len(m.args) == 0 && len(m.kw) == 0 && m.argc == 0 {
		return true
	}
	if len(m.recv) > 0 {
		if c.x == nil || c.x.kind != exprMember || !matchesName(rootName(c.x.x), m.recv) {
			return false
		}
	}
	if m.argc != 0 && len(c.args) != m.argc {
		return false
	}
	for i, re := range m.argRe {
		if i >= len(c.args) {
			return false
		}
		name := ""
		switch c.args[i].kind {
		case exprName, exprMember:
			name = c.args[i].name
		}
		if name == "" || !re.MatchString(name) {
			return false
		}
		if len(m.args) == 0 && len(m.kw) == 0 && len(m.missingKw) == 0 {
			return true
		}
	}
	if len(m.missingKw) > 0 {
		for _, want := range m.missingKw {
			ok := false
			for i, k := range c.kw {
				if k == want {
					ok = true
					if have, isConst := constText(c.args[i]); isConst && (have == "false" || have == "0") {
						ok = false
					}
				}
			}
			if !ok {
				return true
			}
		}
		return false
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
	if m.argc != 0 && len(m.args) == 0 && len(m.kw) == 0 {
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
	return len(m.args) > 0 || len(m.kw) > 0 || m.recvCall != "" || len(m.recv) > 0
}

// checkMisuse reports the unsafe forms of a call to qname (or to a method called field).
func (r *irRun) checkMisuse(c *expr, qname, field string) {
	for _, key := range []string{qname, "?." + field} {
		if key == "?." {
			continue
		}
		for _, m := range r.spec.misuse[key] {
			if m.matches(c, r.argText) {
				r.reportMisuse(c.pos, r.rulesFor(r.spec.name, m), m.detail)
			}
		}
	}
}

var envName = regexp.MustCompile(`(?i)(isdevelopment|isproduction|isstaging|isdev\b|node_env|app_env|rails_env|flask_env|django_debug|\bdebug\b|environment)`)

// envConditional reports whether a condition asks which environment the code runs in.
// Debug settings inside such a branch are meant for development and are not reported.
func envConditional(e *expr) bool {
	if e == nil {
		return false
	}
	if (e.kind == exprName || e.kind == exprMember || e.kind == exprStr) && envName.MatchString(e.name+e.str) {
		return true
	}
	if envConditional(e.x) {
		return true
	}
	for _, a := range e.args {
		if envConditional(a) {
			return true
		}
	}
	return false
}

func (r *irRun) reportMisuse(pos token.Pos, ru rule, detail string) {
	if r.devDepth > 0 && strings.HasSuffix(ru.id, "/debug-enabled") {
		return
	}
	if r.spec.name == "cs" && r.proj != nil && r.proj.globalCSRF && strings.HasSuffix(ru.id, "/csrf-disabled") {
		return // every action is protected by a global filter
	}
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
	for _, s := range am.skip {
		if strings.Contains(strings.ToLower(r.mod.path), s) {
			return
		}
	}
	// A callback that always answers true: ServerCertificateValidationCallback += (a, b, c, d) => true.
	if rhs.kind == exprLambda && rhs.fn != nil && matchesAny("lambda:true", am.vals) {
		if n := len(rhs.fn.body); n > 0 {
			if last := rhs.fn.body[n-1]; last.kind == stmtReturn && last.rhs != nil && last.rhs.kind == exprNum && strings.EqualFold(last.rhs.str, "true") {
				ru := am.rule
				ru.id = strings.Replace(ru.id, "go/", r.spec.name+"/", 1)
				r.reportMisuse(lhs.pos, ru, am.detail)
			}
		}
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
