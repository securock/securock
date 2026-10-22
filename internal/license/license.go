// Package license reads SPDX license expressions and checks them against allow and deny
// lists. It knows a built-in set of common SPDX identifiers; anything else is treated as an
// opaque name that can still be matched by an exact entry in a list.
package license

import (
	"strings"
)

// node is a parsed SPDX expression: a license, or an AND / OR of expressions.
type node struct {
	op       string // "", "AND", "OR"
	id       string // set when op is ""
	children []node
}

// parse reads an SPDX license expression such as "MIT OR (Apache-2.0 AND BSD-3-Clause)".
// "WITH" exceptions are accepted and ignored, since an exception only widens a license.
// ok is false for text that is not an expression, such as a license name in prose.
func parse(expr string) (n node, ok bool) {
	p := parser{tokens: tokenize(expr)}
	if len(p.tokens) == 0 {
		return node{}, false
	}
	n, ok = p.or()
	if !ok || p.pos != len(p.tokens) {
		return node{}, false
	}
	return n, true
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			out = append(out, string(r))
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func isOp(tok, op string) bool { return strings.EqualFold(tok, op) }

func (p *parser) or() (node, bool) { return p.chain("OR", p.and) }

func (p *parser) and() (node, bool) { return p.chain("AND", p.factor) }

func (p *parser) chain(op string, next func() (node, bool)) (node, bool) {
	first, ok := next()
	if !ok {
		return node{}, false
	}
	children := []node{first}
	for isOp(p.peek(), op) {
		p.pos++
		n, ok := next()
		if !ok {
			return node{}, false
		}
		children = append(children, n)
	}
	if len(children) == 1 {
		return first, true
	}
	return node{op: op, children: children}, true
}

func (p *parser) factor() (node, bool) {
	tok := p.peek()
	switch {
	case tok == "":
		return node{}, false
	case tok == "(":
		p.pos++
		n, ok := p.or()
		if !ok || p.peek() != ")" {
			return node{}, false
		}
		p.pos++
		return n, true
	case tok == ")" || isOp(tok, "AND") || isOp(tok, "OR") || isOp(tok, "WITH"):
		return node{}, false
	}
	p.pos++
	n := node{id: Normalize(tok)}
	if isOp(p.peek(), "WITH") {
		p.pos++
		if exc := p.peek(); exc == "" || exc == "(" || exc == ")" || isOp(exc, "AND") || isOp(exc, "OR") {
			return node{}, false
		}
		p.pos++
	}
	return n, true
}

// ids lists every license in the expression.
func (n node) ids() []string {
	if n.op == "" {
		return []string{n.id}
	}
	var out []string
	for _, c := range n.children {
		out = append(out, c.ids()...)
	}
	return out
}

// satisfiable reports whether the expression can be met using only licenses that pass ok:
// one alternative of an OR is enough, every part of an AND is needed.
func (n node) satisfiable(ok func(id string) bool) bool {
	switch n.op {
	case "":
		return ok(n.id)
	case "OR":
		for _, c := range n.children {
			if c.satisfiable(ok) {
				return true
			}
		}
		return false
	default:
		for _, c := range n.children {
			if !c.satisfiable(ok) {
				return false
			}
		}
		return true
	}
}

func (n node) String() string {
	if n.op == "" {
		return n.id
	}
	parts := make([]string, len(n.children))
	for i, c := range n.children {
		parts[i] = c.String()
		if c.op != "" && c.op != n.op {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, " "+n.op+" ")
}

// Verdict is the outcome of checking a license against the rules.
type Verdict int

const (
	Allowed Verdict = iota
	// Denied means every way to satisfy the license needs a denied one.
	Denied
	// NotAllowed means an allow list exists and no way to satisfy the license stays inside it.
	NotAllowed
)

// Check applies the rules to a declared license. An OR gives a choice, so a package that
// offers MIT OR GPL-3.0 passes a rule denying the GPL; an AND gives no choice.
// An empty deny list denies nothing and an empty allow list allows everything.
func Check(declared string, allow, deny []string) (Verdict, []string) {
	n, ok := parse(declared)
	if !ok {
		n = node{id: Normalize(declared)}
	}

	denied := func(id string) bool { return matches(deny, id) }
	if len(deny) > 0 && !n.satisfiable(func(id string) bool { return !denied(id) }) {
		var hit []string
		for _, id := range n.ids() {
			if denied(id) {
				hit = append(hit, id)
			}
		}
		return Denied, hit
	}
	if len(allow) > 0 && !n.satisfiable(func(id string) bool { return matches(allow, id) }) {
		return NotAllowed, n.ids()
	}
	return Allowed, nil
}

// matches reports whether id equals a list entry. A trailing * matches a prefix, so
// "GPL-*" covers every GPL version. Comparison ignores case and uses normalized names.
func matches(list []string, id string) bool {
	id = strings.ToLower(id)
	for _, entry := range list {
		entry = strings.ToLower(Normalize(entry))
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			if strings.HasPrefix(id, prefix) {
				return true
			}
			continue
		}
		if id == entry {
			return true
		}
	}
	return false
}
