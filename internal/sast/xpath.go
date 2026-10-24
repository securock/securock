package sast

import (
	"strconv"
	"strings"
)

// These are validation facts, not vulnerability classes carried by sources.
const (
	noSingleQuote kind = 1 << 30
	noDoubleQuote kind = 1 << 31
)

func forgetXPathContext(t taintSet) taintSet {
	for _, at := range t {
		if at.xpathSafe {
			out := append(taintSet(nil), t...)
			for i := range out {
				out[i].xpathSafe = false
			}
			return out
		}
	}
	return t
}

func quoteFact(quote byte) kind {
	if quote == '\'' {
		return noSingleQuote
	}
	return noDoubleQuote
}

func (r *irRun) quoteFree(e *expr, quote byte, st istate) bool {
	if text, ok := r.strOf(e); ok {
		return !strings.ContainsRune(text, rune(quote))
	}
	if name, field, ok := r.pathOf(e); ok && st.validated(name, field)&quoteFact(quote) != 0 {
		return true
	}
	if e != nil && e.kind == exprCall && e.x.kind == exprMember && e.x.name == "replace" && len(e.args) == 2 {
		for _, kw := range e.kw {
			if kw != "" {
				return false
			}
		}
		old, okOld := r.strOf(e.args[0])
		new, okNew := r.strOf(e.args[1])
		return okOld && okNew && old == string(quote) && !strings.ContainsRune(new, rune(quote))
	}
	return false
}

func (r *irRun) quoteFacts(e *expr, st istate) kind {
	if r.spec.name != "py" {
		return 0
	}
	var facts kind
	for _, quote := range []byte{'\'', '"'} {
		if r.quoteFree(e, quote, st) {
			facts |= quoteFact(quote)
		}
	}
	return facts
}

// Keep the syntax around substitutions. Removing an apostrophe is sufficient
// only inside a single-quoted XPath literal; it does not protect a double-quoted
// literal, a raw expression, SQL, or a subsequent unknown string transformation.
func (r *irRun) xpathConcat(e *expr, st istate) taintSet {
	var parts []*expr
	var flatten func(*expr)
	flatten = func(x *expr) {
		if x != nil && x.kind == exprConcat && (x.str == "+" || x.str == "interpolate") {
			for _, arg := range x.args {
				flatten(arg)
			}
		} else {
			parts = append(parts, x)
		}
	}
	flatten(e)
	var out taintSet
	var quote byte
	var previous byte
	knownContext := true
	for _, part := range parts {
		t := r.eval(part, st).scalar()
		if text, known := r.strOf(part); known {
			for i := range len(text) {
				if quote == 0 && (previous == '(' && text[i] == ':' || previous == 'Q' && text[i] == '{') {
					knownContext = false // comments and URI-qualified names need a full XPath parser
				}
				if quote == 0 && (text[i] == '\'' || text[i] == '"') {
					quote = text[i]
				} else if text[i] == quote {
					quote = 0
				}
				previous = text[i]
			}
		} else if knownContext && quote != 0 && r.quoteFree(part, quote, st) {
			previous = 0
			for i := range t {
				t[i].xpathSafe = true
			}
		} else {
			knownContext = false
			previous = 0
		}
		out = merge(out, t)
	}
	return out
}

// Decode the supported Python escapes rather than comparing literal spellings.
// Unrecognized escapes stay unknown for folding and quote-context checks.
func pythonText(text string, raw bool) (string, bool) {
	if raw {
		return text, true
	}
	var out strings.Builder
	for len(text) > 0 {
		if strings.HasPrefix(text, "\\'") || strings.HasPrefix(text, "\\\"") {
			out.WriteByte(text[1])
			text = text[2:]
			continue
		}
		if strings.HasPrefix(text, "\\\n") {
			text = text[2:]
			continue
		}
		value, _, rest, err := strconv.UnquoteChar(text, 0)
		if err != nil {
			return "", false
		}
		out.WriteRune(value)
		text = rest
	}
	return out.String(), true
}
