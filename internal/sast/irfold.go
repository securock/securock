package sast

import (
	"strconv"
	"strings"
)

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func commonMap[K comparable, V comparable](a, b map[K]V) map[K]V {
	out := map[K]V{}
	for k, v := range a {
		if w, ok := b[k]; ok && v == w {
			out[k] = v
		}
	}
	return out
}

// Constant folding. Test code, feature flags and generated code are full of conditions
// such as (7 * 42) - num > 200 whose outcome is fixed; the branch that cannot run must
// not contribute taint.

func isArith(op string) bool {
	switch op {
	case "-", "*", "/", "%":
		return true
	}
	return false
}

// bin builds an arithmetic or comparison node.
func (l *lowering) bin(n *node, op string, a, b *expr) *expr {
	e := l.mk(exprBin, n)
	e.str, e.args = op, []*expr{a, b}
	return e
}

// cond builds a conditional expression.
func (l *lowering) cond(n *node, c, a, b *expr) *expr {
	e := l.mk(exprCond, n)
	e.x, e.args = c, []*expr{a, b}
	return e
}

func parseIntLiteral(s string) (int64, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "_", ""))
	s = strings.TrimRight(s, "lLuU")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 0, 64)
	return v, err == nil
}

// constInt evaluates an integer expression made of literals and variables that still
// hold a known value.
func (r *irRun) constInt(e *expr) (int64, bool) {
	if e == nil {
		return 0, false
	}
	switch e.kind {
	case exprNum:
		return parseIntLiteral(e.str)
	case exprName:
		v, ok := r.consts[e.name]
		return v, ok
	case exprConcat:
		// string building and addition share a node; two integer operands add.
		if len(e.args) == 2 {
			a, ok1 := r.constInt(e.args[0])
			b, ok2 := r.constInt(e.args[1])
			if ok1 && ok2 {
				return a + b, true
			}
		}
	case exprBin:
		if !isArith(e.str) || len(e.args) != 2 {
			return 0, false
		}
		a, ok1 := r.constInt(e.args[0])
		b, ok2 := r.constInt(e.args[1])
		if !ok1 || !ok2 {
			return 0, false
		}
		switch e.str {
		case "-":
			return a - b, true
		case "*":
			return a * b, true
		case "/":
			if b != 0 {
				return a / b, true
			}
		case "%":
			if b != 0 {
				return a % b, true
			}
		}
	}
	return 0, false
}

// constBool evaluates a condition whose outcome is fixed.
func (r *irRun) constBool(e *expr) (bool, bool) {
	if e == nil {
		return false, false
	}
	switch e.kind {
	case exprNum:
		switch strings.ToLower(e.str) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	case exprNot:
		if v, ok := r.constBool(e.x); ok {
			return !v, true
		}
	case exprAnd:
		a, ok1 := r.constBool(e.args[0])
		b, ok2 := r.constBool(e.args[1])
		switch {
		case ok1 && !a, ok2 && !b:
			return false, true
		case ok1 && ok2:
			return a && b, true
		}
	case exprOr:
		a, ok1 := r.constBool(e.args[0])
		b, ok2 := r.constBool(e.args[1])
		switch {
		case ok1 && a, ok2 && b:
			return true, true
		case ok1 && ok2:
			return a || b, true
		}
	case exprBin:
		if len(e.args) != 2 || isArith(e.str) {
			return false, false
		}
		a, ok1 := r.constInt(e.args[0])
		b, ok2 := r.constInt(e.args[1])
		if !ok1 || !ok2 {
			return false, false
		}
		switch e.str {
		case "<":
			return a < b, true
		case ">":
			return a > b, true
		case "<=":
			return a <= b, true
		case ">=":
			return a >= b, true
		case "==", "===":
			return a == b, true
		case "!=", "!==":
			return a != b, true
		}
	}
	return false, false
}

// assignedNames collects the variables a block may change, so constants held in them are
// forgotten after it.
func assignedNames(list []*stmt, into map[string]bool) {
	for _, s := range list {
		for _, l := range s.lhs {
			if l.kind == exprName {
				into[l.name] = true
			}
		}
		assignedNames(s.then, into)
		assignedNames(s.els, into)
		for _, arm := range s.arms {
			assignedNames(arm, into)
		}
	}
}
