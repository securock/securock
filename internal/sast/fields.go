package sast

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// Bound access paths by widening deeper values to their enclosing object. This
// keeps recursive object-building summaries finite without dropping their taint.
const maxFieldDepth = 8

func widenedField(field string) bool { return strings.Count(field, ".") >= maxFieldDepth }

func fieldJoin(a, b string) string {
	s := a + b
	depth := 0
	for i, c := range s {
		if c == '.' {
			depth++
			if depth > maxFieldDepth {
				return s[:i]
			}
		}
	}
	return s
}

var fieldEncoder = strings.NewReplacer("%", "%25", ".", "%2e")

func fieldPart(s string) string { return "." + fieldEncoder.Replace(s) }

func atomKey(a atom) string { return fmt.Sprintf("%q|%q|%q", a.key, a.field, a.path) }

// selectField projects an object onto one field. A whole-parameter dependency
// becomes a dependency on that parameter's field, rather than on every field.
func (t taintSet) selectField(field string) taintSet {
	if field == "" {
		return t
	}
	var out taintSet
	for _, a := range t {
		switch {
		case a.path == field || strings.HasPrefix(a.path, field+"."):
			a.path = strings.TrimPrefix(a.path, field)
		case a.path == "" || strings.HasPrefix(field, a.path+"."):
			if a.param >= 0 {
				a.field = fieldJoin(a.field, strings.TrimPrefix(field, a.path))
			}
			a.path = ""
		default:
			continue
		}
		out = merge(out, taintSet{a})
	}
	return out
}

func (t taintSet) atField(field string) taintSet {
	var out taintSet
	for _, a := range t {
		a.path = fieldJoin(field, a.path)
		out = merge(out, taintSet{a})
	}
	return out
}

// String construction and unknown library transformations consume the whole
// value, rather than preserving the shape of their input objects.
func (t taintSet) scalar() taintSet {
	var out taintSet
	for _, a := range t {
		a.path = ""
		out = merge(out, taintSet{a})
	}
	return out
}

func readField(t taintSet, stored, wanted string) taintSet {
	if strings.HasPrefix(stored, wanted) {
		return t.atField(strings.TrimPrefix(stored, wanted))
	}
	return t.selectField(strings.TrimPrefix(wanted, stored))
}

type fieldEffect struct {
	param int
	field string
	taint taintSet
}

func (c *funcCtx) effect(param int, field string, t taintSet) {
	if len(t) == 0 {
		return
	}
	for i, e := range c.effects {
		if e.param == param && e.field == field {
			c.effects[i].taint = merge(e.taint, t)
			return
		}
	}
	c.effects = append(c.effects, fieldEffect{param, field, t})
}

func (c *funcCtx) fieldEffects() []fieldEffect {
	sort.Slice(c.effects, func(i, j int) bool {
		a, b := c.effects[i], c.effects[j]
		if a.param != b.param {
			return a.param < b.param
		}
		return a.field < b.field
	})
	return c.effects
}

func substitute(t taintSet, arg func(int, string) taintSet) taintSet {
	var out taintSet
	for _, a := range t {
		if a.param < 0 {
			out = merge(out, taintSet{a})
			continue
		}
		out = merge(out, arg(a.param, a.field).keep(a.kinds).atField(a.path))
	}
	return out
}

func isMetadata(field string) bool { return strings.HasPrefix(field, "\x00") }

func markerKinds(t taintSet) kind {
	var k kind
	for _, a := range t {
		k |= a.kinds
	}
	return k
}

func (s state) validated(obj types.Object, field string) kind {
	var out kind
	for k, t := range s {
		if k.obj == obj && isMarker(k.field) {
			f := strings.TrimPrefix(k.field, markerPrefix)
			if f == field || strings.HasPrefix(field, f+".") {
				out |= markerKinds(t)
			}
		}
	}
	return out
}

func (s istate) validated(name, field string) kind {
	var out kind
	for k, t := range s {
		if k.name == name && isMarker(k.field) {
			f := strings.TrimPrefix(k.field, markerPrefix)
			if f == field || strings.HasPrefix(field, f+".") {
				out |= markerKinds(t)
			}
		}
	}
	return out
}

func (r *irRun) normalizedPath(e *expr) bool {
	if e == nil {
		return false
	}
	if e.kind == exprName {
		return r.cleanPaths[e.name]
	}
	if e.kind == exprCall && e.x != nil {
		q := r.qualified(e.x, istate{})
		switch lastName(e.x) {
		case "getCanonicalPath", "getCanonicalFile", "toRealPath":
			return r.spec.name == "java" || r.spec.name == "kt"
		case "resolve":
			return q == "path.resolve" || q == "path.posix.resolve" || q == "path.win32.resolve" || (r.spec.name == "py" && e.x.kind == exprMember && strings.HasPrefix(r.typeOf(e.x.x, istate{}), "pathlib."))
		case "realpath":
			return q == "os.path.realpath" || q == "posixpath.realpath" || q == "ntpath.realpath" || (r.spec.name == "php" && q == "realpath") || (r.spec.name == "rb" && q == "File.realpath")
		case "GetFullPath":
			return q == "System.IO.Path.GetFullPath"
		}
	}
	return false
}

func (r *irRun) pathBoundary(e *expr) bool {
	if e == nil {
		return false
	}
	if e.kind == exprStr {
		return strings.HasSuffix(e.str, "/")
	}
	if e.kind == exprName {
		return r.boundaries[e.name]
	}
	if e.kind == exprConcat && len(e.args) > 0 {
		return r.pathBoundary(e.args[len(e.args)-1])
	}
	if e.kind == exprMember {
		switch r.qualified(e, istate{}) {
		case "path.sep", "os.sep", "java.io.File.separator", "File.separator", "System.IO.Path.DirectorySeparatorChar":
			return true
		}
	}
	return false
}

func isDeref(e ast.Expr) bool { _, ok := unparen(e).(*ast.StarExpr); return ok }

func (a *analyzer) indexField(e ast.Expr) string {
	if tv := a.info.Types[e]; tv.Value != nil {
		if tv.Value.Kind() == constant.String {
			return fieldPart(constant.StringVal(tv.Value))
		}
		if tv.Value.Kind() == constant.Int {
			return fieldPart(tv.Value.ExactString())
		}
	}
	return ""
}

func (a *analyzer) writeEffect(obj types.Object, field string, t taintSet, st state) {
	if field == "" {
		for _, peer := range st.aliases(obj) {
			if peer != obj {
				st.writeLocal(peer, field, t, true)
			}
		}
	}
	st.write(obj, field, t, true)
	a.recordEffects(obj, field, t, st)
}

func constIndex(e *expr) string {
	if e != nil && (e.kind == exprStr || e.kind == exprNum) {
		return fieldPart(e.str)
	}
	return ""
}

// Kept separate from assignment: a call can update a receiver or reference
// argument but cannot rebind the caller's local variable.
func (r *irRun) writeEffect(name, field string, t taintSet, st istate) {
	if field == "" {
		for _, peer := range st.aliases(name) {
			if peer != name {
				st.writeLocal(peer, field, t, true)
			}
		}
	}
	st.write(name, field, t, true)
	r.recordEffects(name, field, t, st)
}

func addrOperand(e ast.Expr) ast.Expr {
	if u, ok := unparen(e).(*ast.UnaryExpr); ok && u.Op == token.AND {
		return u.X
	}
	return e
}

func (s state) invalidate(obj types.Object, field string) {
	for k := range s {
		if k.obj == obj && isMarker(k.field) && related(strings.TrimPrefix(k.field, markerPrefix), field) {
			delete(s, k)
		}
	}
}

func (s istate) invalidate(name, field string) {
	for k := range s {
		if k.name == name && isMarker(k.field) && related(strings.TrimPrefix(k.field, markerPrefix), field) {
			delete(s, k)
		}
	}
}

func taintSignature(t taintSet) string {
	var b strings.Builder
	for _, a := range t {
		fmt.Fprintf(&b, "%s:%d;", atomKey(a), a.kinds)
	}
	return b.String()
}

func (s state) signature() string {
	var keys []string
	for k, t := range s {
		keys = append(keys, fmt.Sprintf("%d:%s:%s:%s", k.obj.Pos(), k.obj.Name(), k.field, taintSignature(t)))
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

func (s istate) signature() string {
	var keys []string
	for k, t := range s {
		keys = append(keys, fmt.Sprintf("%s:%s:%s", k.name, k.field, taintSignature(t)))
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}
