package sast

import (
	"sort"
	"strings"
)

// These facts are consumed at specific sinks, not cleared from ordinary taint:
// a Python literal can still contain a template payload, and an allowlisted URL
// can become an arbitrary destination after an unknown transformation.
const (
	pythonLiteral  kind = 1 << 28
	parsedRedirect kind = 1 << 29
	parsedURLField      = "\x00parsed-url"
)

type guardClause struct {
	value *expr
	truth bool
}

func guardClauses(e *expr, truth bool) []guardClause {
	if e == nil {
		return nil
	}
	if e.kind == exprNot {
		return guardClauses(e.x, !truth)
	}
	if e.kind == exprAnd && truth || e.kind == exprOr && !truth {
		return append(guardClauses(e.args[0], truth), guardClauses(e.args[1], truth)...)
	}
	return []guardClause{{e, truth}}
}

func (r *irRun) pythonGuards(e *expr, truth bool, st istate) []validatedIR {
	if r.spec.name != "py" {
		return nil
	}
	clauses := guardClauses(e, truth)
	type literalKey struct{ name, quote string }
	literals := map[literalKey]uint8{}
	hosts, schemes := map[string]bool{}, map[string]bool{}
	values := map[string]*expr{}
	for _, clause := range clauses {
		c := clause.value
		var value *expr
		var quote string
		var bit uint8
		switch {
		case clause.truth && c.kind == exprIn && c.str == "prefix" && len(c.args) == 1:
			value, quote, bit = c.args[0], c.x.str, 1
			if c.x.kind != exprStr || c.x.unknownText {
				continue
			}
		case clause.truth && c.kind == exprCall && c.x.kind == exprMember && c.x.name == "endswith" && len(c.args) == 1 && positionalOnly(c):
			value, quote, bit = c.x.x, c.args[0].str, 2
			if c.args[0].kind != exprStr || c.args[0].unknownText {
				continue
			}
		case !clause.truth && c.kind == exprIn && c.str == "" && len(c.args) == 1 && c.x.kind == exprIndex && len(c.x.args) == 1:
			slice := c.x.args[0]
			if slice.kind != exprOther || slice.str != "interior-slice" || c.args[0].kind != exprStr || c.args[0].unknownText {
				continue
			}
			value, quote, bit = c.x.x, c.args[0].str, 4
		}
		if value != nil && value.kind == exprName && (quote == "'" || quote == `"`) {
			literals[literalKey{value.name, quote}] |= bit
			values[value.name] = value
		}
		if clause.truth && c.kind == exprIn && c.str == "" && len(c.args) == 1 {
			member := c.args[0]
			if member.kind == exprMember && member.name == "netloc" && member.x.kind == exprName {
				if allowed, ok := r.literalStrings(c.x, st); ok && len(allowed) > 0 {
					safe := true
					for _, host := range allowed {
						safe = safe && host != "" && !strings.ContainsAny(host, "\\/@?# \t\r\n")
					}
					hosts[member.x.name] = safe
				}
			}
		}
		if c.kind == exprBin && len(c.args) == 2 && (c.str == "==" && clause.truth || c.str == "!=" && !clause.truth) {
			member, literal := c.args[0], c.args[1]
			if member.kind == exprStr {
				member, literal = literal, member
			}
			if member.kind == exprMember && member.name == "scheme" && member.x.kind == exprName && literal.kind == exprStr && !literal.unknownText && (literal.str == "https" || literal.str == "http") {
				schemes[member.x.name] = true
			}
		}
	}
	var out []validatedIR
	for key, bits := range literals {
		// Prefix, suffix and an apostrophe-free interior together prove a single
		// literal (or invalid syntax), rather than arbitrary executable Python.
		if bits == 7 {
			out = append(out, validatedIR{values[key.name], pythonLiteral})
		}
	}
	for name, host := range hosts {
		origin := st[ikey{name, parsedURLField}]
		if host && schemes[name] && len(origin) == 1 {
			out = append(out, validatedIR{&expr{kind: exprName, name: origin[0].refName}, parsedRedirect})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].value.name != out[j].value.name {
			return out[i].value.name < out[j].value.name
		}
		return out[i].kinds < out[j].kinds
	})
	return out
}

func positionalOnly(e *expr) bool {
	for _, kw := range e.kw {
		if kw != "" {
			return false
		}
	}
	return true
}

func (r *irRun) literalStrings(e *expr, st istate) ([]string, bool) {
	var out []string
	if e.kind == exprSequence {
		for _, item := range e.args {
			text, ok := r.strOf(item)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	}
	if e.kind == exprName {
		if size, ok := st.sequenceSize(e.name); ok {
			for i := range size {
				text := st[ikey{e.name, sequenceTextField(i)}]
				if len(text) != 1 {
					return nil, false
				}
				out = append(out, text[0].key)
			}
			return out, true
		}
	}
	return nil, false
}

func (r *irRun) recordParsedURL(lhs, rhs *expr, st istate) {
	if r.spec.name != "py" || lhs.kind != exprName || rhs == nil || rhs.kind != exprCall || len(rhs.args) != 1 || !positionalOnly(rhs) || rhs.args[0].kind != exprName || lhs.name == rhs.args[0].name || r.shadow[rootName(rhs.x)] {
		return
	}
	q, _, _ := r.resolve(rhs.x, st)
	if q == "urllib.parse.urlparse" || q == "urllib.parse.urlsplit" {
		st[ikey{lhs.name, parsedURLField}] = taintSet{{key: rhs.args[0].name, refName: rhs.args[0].name}}
	}
}
