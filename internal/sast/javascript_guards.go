package sast

import "strings"

func (r *irRun) javascriptTypeGuard(e *expr, truth bool) []validatedIR {
	if r.spec.name != "js" || e == nil || e.kind != exprBin || len(e.args) != 2 {
		return nil
	}
	switch e.str {
	case "==", "===":
	case "!=", "!==":
		truth = !truth
	default:
		return nil
	}
	if !truth {
		return nil
	}
	a, b := e.args[0], e.args[1]
	if b.kind == exprTypeof {
		a, b = b, a
	}
	if a.kind == exprTypeof && b.kind == exprStr && !b.unknownText && b.str == "string" {
		// A string cannot supply query-operator keys. It can still carry SQL,
		// shell or JavaScript text, including a MongoDB $where expression. Only
		// vouch for a directly named value: typeof x.toString() says nothing
		// about x, and markValid would otherwise widen the fact to its root.
		if _, _, ok := r.pathOf(a.x); !ok {
			return nil
		}
		return []validatedIR{{a.x, kNoSQL | kProto | kMass}}
	}
	return nil
}

// Incompatible prefixes prove an unreachable branch, not a sanitized value.
// Only conjunctions of positive prefix checks (or disjunctions of their
// negations) on the same access path participate; unknown checks stay opaque.
func (r *irRun) javascriptCondition(e *expr) (bool, bool) {
	if r.spec.name != "js" || e == nil {
		return false, false
	}
	if e.kind == exprNot {
		value, known := r.javascriptCondition(e.x)
		return !value, known
	}
	if e.kind != exprAnd && e.kind != exprOr {
		return false, false
	}
	type prefix struct{ name, field, text string }
	var checks []prefix
	var collect func(*expr) bool
	collect = func(c *expr) bool {
		if c == nil || len(checks) >= 64 {
			return false
		}
		if c.kind == e.kind && len(c.args) == 2 {
			return collect(c.args[0]) && collect(c.args[1])
		}
		if e.kind == exprOr {
			if c.kind != exprNot {
				return false
			}
			c = c.x
		}
		if c == nil || c.kind != exprIn || c.str != "prefix" || len(c.args) != 1 {
			return false
		}
		text, known := r.strOf(c.x)
		name, field, path := r.pathOf(c.args[0])
		if !known || !path || strings.Contains(text, "\\") {
			return false
		}
		if ty := r.types[name]; ty != "" && ty != "string" && ty != "String" && ty != "any" && ty != "unknown" {
			return false // a class can define a method with different semantics
		}
		checks = append(checks, prefix{name, field, text})
		return true
	}
	if !collect(e) {
		return false, false
	}
	for i, a := range checks {
		for _, b := range checks[:i] {
			if a.name == b.name && a.field == b.field && !strings.HasPrefix(a.text, b.text) && !strings.HasPrefix(b.text, a.text) {
				return e.kind == exprOr, true
			}
		}
	}
	return false, false
}
