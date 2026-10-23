package sast

import (
	"regexp"
	"strings"

	"github.com/securock/securock/internal/finding"
)

var (
	ruleInsecureRandom = rule{"sast:go/insecure-random", "CWE-338", "Predictable random number used for a secret",
		"Use the operating system's cryptographic generator (crypto/rand, secrets, SecureRandom, random_bytes, SecureRandom.hex).", finding.SeverityMedium}
	ruleToctou = rule{"sast:go/toctou", "CWE-367", "File is checked and then used by name",
		"Open the file once and operate on the handle (O_EXCL, O_NOFOLLOW), instead of checking the path and acting on it later.", finding.SeverityLow}
	ruleCORS = rule{"sast:go/cors-misconfiguration", "CWE-942", "Credentialed CORS allows any origin",
		"List the exact origins that may send credentials instead of reflecting the request's origin.", finding.SeverityMedium}
)

func ruleFor2(lang string, r rule) rule {
	r.id = strings.Replace(r.id, "go/", lang+"/", 1)
	return r
}

// secretish names things whose value must not be guessable.
var secretish = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|passcode|session|nonce|salt|otp|csrf|apikey|api_key|auth|credential|reset|verification|signature|(private|encryption|signing|access|crypto|secret)_?key)`)

// checkExtras runs the checks that depend on context or order: predictable randomness in
// something secret-looking, a file checked and then used, an unhardened XML parser, and
// a recursive merge that walks request keys.
func (r *irRun) checkExtras(c *expr, qname, field string, fn *expr, st istate) {
	if r.spec.weakRNG[qname] && (secretish.MatchString(r.ctx.label) || secretish.MatchString(r.lhsName)) {
		r.reportMisuse(c.pos, ruleFor2(r.spec.name, ruleInsecureRandom), qname+" is predictable and is used to make a "+secretWord(r.ctx.label, r.lhsName))
	}

	if r.spec.fsCheck[qname] || (field != "" && r.spec.fsCheck["?."+field]) {
		if k, ok := r.fsKey(c, fn); ok {
			r.checked[k] = true
		}
	}
	if r.spec.fsUse[qname] || (field != "" && r.spec.fsUse["?."+field]) {
		if k, ok := r.fsKey(c, fn); ok && r.checked[k] {
			r.reportMisuse(c.pos, ruleFor2(r.spec.name, ruleToctou), "the path was checked earlier in this function and can change before it is used here")
		}
	}

	if r.spec.xxeFactories[qname] {
		r.xxeFactories = append(r.xxeFactories, c.pos)
	}
	if field == "setFeature" || field == "setAttribute" || field == "setProperty" || field == "setXIncludeAware" || field == "setExpandEntityReferences" {
		for _, a := range c.args {
			if t, ok := constText(a); ok && (strings.Contains(t, "external") || strings.Contains(t, "doctype") || strings.Contains(t, "dtd") || strings.Contains(t, "entity")) {
				r.xxeHardened = true
			}
		}
	}
}

func secretWord(names ...string) string {
	for _, n := range names {
		if m := secretish.FindString(n); m != "" {
			return strings.ToLower(m)
		}
	}
	return "secret"
}

// fsKey identifies the path a file call acts on: its first argument, or its receiver.
func (r *irRun) fsKey(c *expr, fn *expr) (string, bool) {
	var target *expr
	switch {
	case len(c.args) > 0:
		target = c.args[0]
	case fn != nil && fn.kind == exprMember:
		target = fn.x
	}
	if target == nil {
		return "", false
	}
	name, f, ok := r.pathOf(target)
	return name + "|" + f, ok
}
