package sast

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// flow is one step of the path a value took, newest first.
type flow struct {
	pos  token.Pos
	msg  string
	prev *flow
}

// atom is one origin of taint: an untrusted source (param < 0) or a parameter of the
// function being analyzed (param >= 0, resolved at call sites through summaries).
type atom struct {
	key   string
	param int
	kinds kind
	flow  *flow
}

// taintSet is sorted by key so every iteration over it is deterministic.
type taintSet []atom

func merge(a, b taintSet) taintSet {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make(taintSet, 0, len(a)+len(b))
	out = append(out, a...)
	for _, x := range b {
		i := slices.IndexFunc(out, func(y atom) bool { return y.key == x.key })
		if i < 0 {
			out = append(out, x)
		} else if out[i].kinds|x.kinds != out[i].kinds {
			out[i].kinds |= x.kinds
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func (t taintSet) clear(k kind) taintSet {
	var out taintSet
	for _, a := range t {
		if a.kinds &^= k; a.kinds != 0 {
			out = append(out, a)
		}
	}
	return out
}

// keep returns the part of each atom that is in k.
func (t taintSet) keep(k kind) taintSet {
	var out taintSet
	for _, a := range t {
		if a.kinds &= k; a.kinds != 0 {
			out = append(out, a)
		}
	}
	return out
}

func (t taintSet) step(pos token.Pos, msg string) taintSet {
	out := make(taintSet, len(t))
	for i, a := range t {
		a.flow = &flow{pos: pos, msg: msg, prev: a.flow}
		out[i] = a
	}
	return out
}

// appendFlow returns base followed by the steps of tail (both newest first).
func appendFlow(base, tail *flow) *flow {
	var steps []*flow
	for f := tail; f != nil; f = f.prev {
		steps = append(steps, f)
	}
	for _, s := range slices.Backward(steps) {
		base = &flow{pos: s.pos, msg: s.msg, prev: base}
	}
	return base
}

type vkey struct {
	obj   types.Object
	field string
}

type state map[vkey]taintSet

func (s state) clone() state {
	out := make(state, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// replace sets s to the merge of two branch states, which both started as clones of s.
func (s state) replace(a, b state) {
	clear(s)
	s.union(a)
	s.union(b)
	// A value is validated after the branches only if it was validated in both.
	for k := range a {
		if isMarker(k.field) {
			if _, both := b[k]; both {
				s[k] = a[k]
			}
		}
	}
}

func (s state) union(o state) {
	for k, v := range o {
		if isMarker(k.field) {
			continue
		}
		s[k] = merge(s[k], v)
	}
}

// A marker records that a value has been validated on this path. Sources are recomputed
// every time they are read (r.URL, f.Name), so clearing stored taint is not enough: the
// read has to know the value passed a check.
const markerPrefix = "\x00v:"

func isMarker(field string) bool { return strings.HasPrefix(field, markerPrefix) }

func (s state) mark(obj types.Object, field string) {
	s[vkey{obj, markerPrefix + field}] = taintSet{{key: "valid"}}
}

func (s state) marked(obj types.Object, field string) bool {
	_, ok := s[vkey{obj, markerPrefix + field}]
	return ok
}

// related reports whether two field paths overlap: one is a prefix of the other.
func related(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

func (s state) read(obj types.Object, field string) taintSet {
	var out taintSet
	for k, v := range s {
		if k.obj == obj && related(k.field, field) {
			out = merge(out, v)
		}
	}
	return out
}

func (s state) write(obj types.Object, field string, t taintSet, weak bool) {
	if !weak {
		for k := range s {
			if k.obj == obj && (k.field == field || strings.HasPrefix(k.field, field+".")) {
				delete(s, k)
			}
		}
	}
	if len(t) > 0 {
		k := vkey{obj, field}
		s[k] = merge(s[k], t)
	}
}

// paramSink records that a function's parameter reaches a dangerous call.
type paramSink struct {
	param int
	kind  kind
	name  string
	pos   token.Pos
	flow  *flow // steps from the parameter to the sink, newest first
}

type summary struct {
	ret   taintSet
	sinks []paramSink
}

func (s *summary) signature() string {
	var b strings.Builder
	for _, a := range s.ret {
		fmt.Fprintf(&b, "r%s:%d;", a.key, a.kinds)
	}
	for _, k := range s.sinks {
		fmt.Fprintf(&b, "s%d:%d:%s:%d;", k.param, k.kind, k.name, k.pos)
	}
	return b.String()
}

type funcCtx struct {
	oks     map[types.Object]ast.Expr // "v, ok := m[k]": ok validates k
	cleaned map[types.Object]bool     // variables holding the result of filepath.Join/Clean/Abs
	loopAcc state                     // states at break/continue in the innermost loop
	name    string
	label   string
	ret     taintSet
	sinks   []paramSink
	litDeep int
}

// recvParam is the parameter index that stands for a method's receiver in summaries.
const recvParam = 1 << 20

// impl is a concrete method that may be the target of an interface call.
type impl struct {
	recv types.Type // pointer to the receiver type, whose method set covers both kinds
	key  string
}

// shared holds what every function analysis in a run reads and extends.
type shared struct {
	// declTypes holds the type as written for each parameter and variable, so a method
	// call on a value whose package is not available can still be named by the import path.
	declTypes map[types.Object]ast.Expr
	sums      map[string]*summary
	methods   map[string][]impl // method name -> concrete methods, for interface calls
	globals   map[types.Object]taintSet
	regexps   map[types.Object]string
}

type analyzer struct {
	*shared
	langName string
	fset     *token.FileSet
	info     *types.Info
	rel      func(token.Pos) string
	found    map[string]finding.Finding
	ctx      *funcCtx
}

func (a *analyzer) lang() string {
	if a.langName == "" {
		return "go"
	}
	return a.langName
}

func (a *analyzer) source(pos token.Pos, desc string) taintSet {
	return taintSet{{key: fmt.Sprintf("s%d", pos), param: -1, kinds: kindsFor(desc), flow: &flow{pos: pos, msg: "untrusted data: " + desc}}}
}

func (a *analyzer) loc(pos token.Pos) *finding.Location {
	p := a.fset.Position(pos)
	return &finding.Location{File: a.rel(pos), Line: p.Line, Column: p.Column}
}

func (a *analyzer) steps(f *flow) []finding.Step {
	var out []finding.Step
	for ; f != nil; f = f.prev {
		l := a.loc(f.pos)
		out = append(out, finding.Step{Location: *l, Message: f.msg})
	}
	slices.Reverse(out)
	return out
}

// inert reports whether a value of type t cannot carry an injection payload.
func inert(t types.Type) bool {
	if t == nil {
		return false
	}
	if b, ok := t.Underlying().(*types.Basic); ok {
		return b.Info()&(types.IsNumeric|types.IsBoolean) != 0
	}
	return types.Identical(t, types.Universe.Lookup("error").Type())
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// pathOf resolves an addressable expression to its root variable and field path.
func (a *analyzer) pathOf(e ast.Expr) (obj types.Object, field string, weak, ok bool) {
	switch e := unparen(e).(type) {
	case *ast.Ident:
		o := a.info.Defs[e]
		if o == nil {
			o = a.info.Uses[e]
		}
		if v, isVar := o.(*types.Var); isVar && e.Name != "_" {
			return v, "", false, true
		}
	case *ast.SelectorExpr:
		if id, isID := e.X.(*ast.Ident); isID {
			if _, isPkg := a.info.Uses[id].(*types.PkgName); isPkg {
				return nil, "", false, false
			}
		}
		o, f, w, k := a.pathOf(e.X)
		if k {
			return o, f + "." + e.Sel.Name, w, true
		}
	case *ast.StarExpr:
		return a.pathOf(e.X)
	case *ast.IndexExpr:
		o, f, _, k := a.pathOf(e.X)
		return o, f, true, k
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return a.pathOf(e.X)
		}
	}
	return nil, "", false, false
}

func isGlobal(o types.Object) bool {
	return o.Pkg() != nil && o.Parent() == o.Pkg().Scope()
}

// readVar reads a local through the state and a package-level variable through the
// taint any function has stored in it.
func (a *analyzer) readVar(st state, obj types.Object, field string) taintSet {
	t := st.read(obj, field)
	if isGlobal(obj) {
		t = merge(t, a.globals[obj])
	}
	return t
}

func (a *analyzer) calleeName(fun ast.Expr) (name string, recv ast.Expr) {
	switch f := unparen(fun).(type) {
	case *ast.Ident:
		switch o := a.info.Uses[f].(type) {
		case *types.Func:
			return normalize(o.FullName()), nil
		case *types.TypeName:
			if o.Pkg() != nil {
				return normalize(o.Pkg().Path() + "." + o.Name()), nil
			}
		}
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			if pn, ok := a.info.Uses[id].(*types.PkgName); ok {
				if fn, ok := a.info.Uses[f.Sel].(*types.Func); ok {
					return normalize(fn.FullName()), nil
				}
				return normalize(pn.Imported().Path() + "." + f.Sel.Name), nil
			}
		}
		if sel := a.info.Selections[f]; sel != nil {
			if fn, ok := sel.Obj().(*types.Func); ok {
				return normalize(fn.FullName()), f.X
			}
		}
		if name := a.unresolvedMethod(f); name != "" {
			return name, f.X
		}
		return "", f.X
	}
	return "", nil
}

// eval returns the taint of e and reports any sink reached while evaluating it.
func (a *analyzer) eval(e ast.Expr, st state) taintSet {
	if e == nil {
		return nil
	}
	if tv, ok := a.info.Types[e]; ok {
		if tv.Value != nil || inert(tv.Type) {
			// Still walk calls and literals for the sinks they contain.
			a.evalRaw(e, st)
			return nil
		}
	}
	return a.evalRaw(e, st)
}

func (a *analyzer) evalRaw(e ast.Expr, st state) taintSet {
	switch e := e.(type) {
	case *ast.Ident:
		if obj, f, _, ok := a.pathOf(e); ok {
			return a.readVar(st, obj, f)
		}
	case *ast.ParenExpr:
		return a.eval(e.X, st)
	case *ast.SelectorExpr:
		return a.evalSelector(e, st)
	case *ast.CallExpr:
		return a.evalCall(e, st)
	case *ast.BinaryExpr:
		return merge(a.eval(e.X, st), a.eval(e.Y, st))
	case *ast.UnaryExpr:
		return a.eval(e.X, st)
	case *ast.StarExpr:
		return a.eval(e.X, st)
	case *ast.SliceExpr:
		a.eval(e.Low, st)
		a.eval(e.High, st)
		return a.eval(e.X, st)
	case *ast.IndexExpr:
		a.eval(e.Index, st)
		return a.eval(e.X, st)
	case *ast.TypeAssertExpr:
		return a.eval(e.X, st)
	case *ast.KeyValueExpr:
		return a.eval(e.Value, st)
	case *ast.CompositeLit:
		var out taintSet
		for _, el := range e.Elts {
			out = merge(out, a.eval(el, st))
		}
		return out
	case *ast.FuncLit:
		a.walkLit(e, st, nil)
	}
	return nil
}

func (a *analyzer) evalSelector(e *ast.SelectorExpr, st state) taintSet {
	if id, ok := e.X.(*ast.Ident); ok {
		if pn, ok := a.info.Uses[id].(*types.PkgName); ok {
			name := pn.Imported().Path() + "." + e.Sel.Name
			if desc, ok := sourceVars[name]; ok {
				return a.source(e.Pos(), desc)
			}
			return nil
		}
	}
	validated := false
	if obj, f, _, ok := a.pathOf(e); ok {
		validated = st.marked(obj, f)
	}
	if e.Sel.Name == "Name" && isArchiveEntry(a.info.TypeOf(e.X)) && !validated {
		return a.source(e.Pos(), archiveDesc)
	}
	if desc, ok := requestFields[e.Sel.Name]; ok && isRequest(a.info.TypeOf(e.X)) && !validated {
		return a.source(e.Pos(), desc)
	}
	if obj, f, _, ok := a.pathOf(e); ok {
		t := a.readVar(st, obj, f)
		// A source field anywhere along the chain taints everything beneath it.
		for x := ast.Expr(e); ; {
			sel, ok := x.(*ast.SelectorExpr)
			if !ok {
				break
			}
			if desc, ok := requestFields[sel.Sel.Name]; ok && isRequest(a.info.TypeOf(sel.X)) {
				t = merge(t, a.source(sel.Pos(), desc))
			}
			x = unparen(sel.X)
		}
		return t
	}
	return a.eval(e.X, st)
}

// isArchiveEntry reports whether t is a zip or tar entry header, whose Name is attacker
// chosen.
// unresolvedMethod names a method call such as c.FindOne(...) when c's type comes from a
// package that could not be loaded, from the type as it was written: "(*pkg.Type).Method".
func (a *analyzer) unresolvedMethod(f *ast.SelectorExpr) string {
	id, ok := f.X.(*ast.Ident)
	if !ok {
		return ""
	}
	if b, isBasic := a.info.TypeOf(id).(*types.Basic); a.info.TypeOf(id) != nil && !(isBasic && b.Kind() == types.Invalid) {
		return ""
	}
	te := a.declTypes[a.info.Uses[id]]
	if te == nil {
		return ""
	}
	ptr := false
	if st, isStar := te.(*ast.StarExpr); isStar {
		te, ptr = st.X, true
	}
	se, ok := te.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkgID, ok := se.X.(*ast.Ident)
	if !ok {
		return ""
	}
	pn, ok := a.info.Uses[pkgID].(*types.PkgName)
	if !ok {
		return ""
	}
	typ := normalize(pn.Imported().Path()) + "." + se.Sel.Name
	if ptr {
		return "(*" + typ + ")." + f.Sel.Name
	}
	return "(" + typ + ")." + f.Sel.Name
}

func isArchiveEntry(t types.Type) bool {
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	switch types.TypeString(t, nil) {
	case "archive/zip.File", "archive/zip.FileHeader", "archive/tar.Header":
		return true
	}
	return false
}

func isRequest(t types.Type) bool {
	if t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	return types.TypeString(t, nil) == "net/http.Request"
}

func (a *analyzer) evalCall(c *ast.CallExpr, st state) taintSet {
	if lit, ok := unparen(c.Fun).(*ast.FuncLit); ok {
		args := make([]taintSet, len(c.Args))
		for i, x := range c.Args {
			args[i] = a.eval(x, st)
		}
		a.walkLit(lit, st, args)
		return nil
	}
	if tv, ok := a.info.Types[c.Fun]; ok && tv.IsType() {
		return a.evalConversion(c, st)
	}
	name, recvExpr := a.calleeName(c.Fun)

	argT := make([]taintSet, len(c.Args))
	for i, x := range c.Args {
		argT[i] = a.eval(x, st)
	}
	var recvT taintSet
	if recvExpr != nil {
		recvT = a.eval(recvExpr, st)
	} else if _, isSel := unparen(c.Fun).(*ast.SelectorExpr); isSel && name == "" {
		recvT = a.eval(unparen(c.Fun).(*ast.SelectorExpr).X, st)
	}

	if s, ok := sinks[name]; ok {
		a.checkSink(c, name, s, argT)
	}
	if f, ok := fills[name]; ok {
		a.applyFill(c, f, argT, recvT, recvExpr, st)
	}

	if desc, ok := sourceCalls[name]; ok {
		return a.source(c.Pos(), desc)
	}
	if sk, ok := sinks[name]; ok && sk.kind != kXSS {
		// What a query, file read or request returns is data from elsewhere, not the
		// payload that was passed in.
		return nil
	}

	all := recvT
	for _, t := range argT {
		all = merge(all, t)
	}
	if k, ok := sanitizers[name]; ok {
		return all.clear(k)
	}
	if sum, ok := a.sums[name]; ok {
		return a.applySummary(c, name, sum, argT, recvT)
	}
	if recvExpr != nil {
		if t, ok := a.dispatch(c, recvExpr, argT, recvT); ok {
			return t
		}
	}
	if bi, ok := a.info.Uses[identOf(c.Fun)].(*types.Builtin); ok {
		switch bi.Name() {
		case "append":
			return all
		case "len", "cap", "make", "new", "delete", "close", "panic", "print", "println", "copy", "min", "max", "clear", "recover":
			return nil
		}
	}
	return all
}

func identOf(e ast.Expr) *ast.Ident {
	id, _ := unparen(e).(*ast.Ident)
	return id
}

func (a *analyzer) evalConversion(c *ast.CallExpr, st state) taintSet {
	if len(c.Args) != 1 {
		return nil
	}
	t := a.eval(c.Args[0], st)
	name := ""
	if tn := typeNameOf(a.info.TypeOf(c.Fun)); tn != "" {
		name = normalize(tn)
	}
	if s, ok := sinks[name]; ok {
		a.checkSink(c, name, s, []taintSet{t})
	}
	return t
}

func typeNameOf(t types.Type) string {
	if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil {
		return n.Obj().Pkg().Path() + "." + n.Obj().Name()
	}
	return ""
}

func (a *analyzer) applyFill(c *ast.CallExpr, f fill, argT []taintSet, recvT taintSet, recvExpr ast.Expr, st state) {
	var t taintSet
	switch f.from {
	case fromRecv:
		t = recvT
	case fromSource:
		t = a.source(c.Pos(), f.src)
	default:
		if f.from >= 0 && f.from < len(argT) {
			t = argT[f.from]
		}
	}
	if len(t) == 0 {
		return
	}
	var target ast.Expr
	if f.to == toRecv {
		target = recvExpr
	} else if f.to >= 0 && f.to < len(c.Args) {
		target = c.Args[f.to]
	}
	if target == nil {
		return
	}
	if obj, field, _, ok := a.pathOf(target); ok {
		st.write(obj, field, t, true)
	}
}

// whenHolds reports whether a call's constant string arguments match a sink's condition.
func (a *analyzer) whenHolds(c *ast.CallExpr, when map[int][]string) bool {
	for i, want := range when {
		if i >= len(c.Args) {
			return false
		}
		tv := a.info.Types[c.Args[i]]
		if tv.Value == nil || tv.Value.Kind() != constant.String || !matchesAny(strings.ToLower(constant.StringVal(tv.Value)), want) {
			return false
		}
	}
	return true
}

func (a *analyzer) checkSink(c *ast.CallExpr, name string, s sink, argT []taintSet) {
	if len(s.when) > 0 && !a.whenHolds(c, s.when) {
		return
	}
	if s.writer && (len(c.Args) == 0 || types.TypeString(a.info.TypeOf(c.Args[0]), nil) != "net/http.ResponseWriter") {
		return
	}
	idx := slices.Clone(s.args)
	if s.rest {
		for i := s.args[len(s.args)-1] + 1; i < len(argT); i++ {
			idx = append(idx, i)
		}
	}
	if s.shellFrom > 0 && len(s.args) > 0 && s.args[0] < len(c.Args) {
		if tv := a.info.Types[c.Args[s.args[0]]]; tv.Value != nil && shells[strings.Trim(tv.Value.ExactString(), `"`)] {
			for i := s.shellFrom; i < len(argT); i++ {
				idx = append(idx, i)
			}
		}
	}
	for _, i := range idx {
		if i >= len(argT) {
			continue
		}
		for _, at := range argT[i] {
			if hit := at.kinds & s.kind; hit != 0 {
				a.reachSink(c.Pos(), name, hit, at, nil)
			}
		}
	}
}

// reachSink handles one tainted value arriving at a sink. A real source becomes a
// finding; a parameter becomes part of the enclosing function's summary. inner holds the
// steps taken inside a callee when the sink was reached through a summary.
func (a *analyzer) reachSink(pos token.Pos, name string, hit kind, at atom, inner *flow) {
	trace := appendFlow(at.flow, inner)
	if at.param >= 0 {
		a.ctx.sinks = append(a.ctx.sinks, paramSink{param: at.param, kind: hit, name: name, pos: pos, flow: trace})
		return
	}
	for k := kind(1); k <= kLast; k <<= 1 {
		if hit&k == 0 {
			continue
		}
		r := ruleFor(k, a.lang())
		trace := &flow{pos: pos, msg: "reaches " + name + " (" + r.cwe + ")", prev: trace}
		l := a.loc(pos)
		key := fmt.Sprintf("%s|%s|%d|%d", r.id, l.File, l.Line, l.Column)
		if _, dup := a.found[key]; dup {
			continue
		}
		a.found[key] = finding.Finding{
			ID:          r.id,
			Severity:    r.sev,
			Title:       r.title + " (" + r.cwe + ")",
			Detail:      fmt.Sprintf("%s reaches %s without sanitization", strings.TrimPrefix(at.flow.root().msg, "untrusted data: "), shortName(name)),
			Subject:     fmt.Sprintf("%s#%s/%s", l.File, a.ctx.label, shortName(name)),
			Remediation: r.fix,
			Location:    l,
			Trace:       a.steps(trace),
		}
	}
}

func (f *flow) root() *flow {
	if f == nil {
		return &flow{}
	}
	for f.prev != nil {
		f = f.prev
	}
	return f
}

var pkgPrefix = regexp.MustCompile(`[A-Za-z0-9_.\-]+/`)

// shortName drops package paths: "(*database/sql.DB).Query" becomes "(*sql.DB).Query".
func shortName(n string) string {
	return pkgPrefix.ReplaceAllString(n, "")
}

func (a *analyzer) applySummary(c *ast.CallExpr, name string, sum *summary, argT []taintSet, recvT taintSet) taintSet {
	np, variadic := 0, false
	if sig, ok := a.info.TypeOf(c.Fun).(*types.Signature); ok {
		np, variadic = sig.Params().Len(), sig.Variadic()
	}
	// argAt is the taint feeding parameter p; variadic extras all feed the last one.
	argAt := func(p int) taintSet {
		if p == recvParam {
			return recvT
		}
		var out taintSet
		for j, t := range argT {
			if pj := min(j, max(np-1, 0)); variadic && pj == p || !variadic && j == p {
				out = merge(out, t)
			}
		}
		return out
	}
	callStep := "passed to " + shortName(name)
	for _, sk := range sum.sinks {
		for _, at := range argAt(sk.param) {
			if hit := at.kinds & sk.kind; hit != 0 {
				at.flow = &flow{pos: c.Pos(), msg: callStep, prev: at.flow}
				a.reachSink(sk.pos, sk.name, hit, at, sk.flow)
			}
		}
	}
	var out taintSet
	for _, r := range sum.ret {
		if r.param < 0 {
			out = merge(out, taintSet{{key: r.key, param: -1, kinds: r.kinds, flow: &flow{pos: c.Pos(), msg: "returned by " + shortName(name), prev: r.flow}}})
			continue
		}
		out = merge(out, argAt(r.param).clear(^r.kinds).step(c.Pos(), "flows through "+shortName(name)))
	}
	return out
}

// dispatch applies the summaries of every concrete method an interface call may reach.
func (a *analyzer) dispatch(c *ast.CallExpr, recvExpr ast.Expr, argT []taintSet, recvT taintSet) (taintSet, bool) {
	sel, ok := unparen(c.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	// The type is nil when the receiver comes from a package that was not loaded.
	t := a.info.TypeOf(recvExpr)
	if t == nil {
		return nil, false
	}
	iface, ok := t.Underlying().(*types.Interface)
	if !ok {
		return nil, false
	}
	var out taintSet
	found := false
	for _, m := range a.methods[sel.Sel.Name] {
		sum, ok := a.sums[m.key]
		if !ok || !types.Implements(m.recv, iface) {
			continue
		}
		found = true
		out = merge(out, a.applySummary(c, m.key, sum, argT, recvT))
	}
	return out, found
}

// walkLit analyzes a function literal in place. Captured variables share the enclosing
// state, so a closure that taints one is seen by the code after it.
func (a *analyzer) walkLit(lit *ast.FuncLit, st state, args []taintSet) {
	inner := st.clone()
	i := 0
	for _, f := range lit.Type.Params.List {
		for _, n := range f.Names {
			if o, ok := a.info.Defs[n].(*types.Var); ok && i < len(args) && len(args[i]) > 0 {
				inner.write(o, "", args[i], false)
			}
			i++
		}
		if len(f.Names) == 0 {
			i++
		}
	}
	a.ctx.litDeep++
	a.block(lit.Body.List, inner)
	a.ctx.litDeep--
	st.union(inner)
}

func (a *analyzer) assign(lhs ast.Expr, t taintSet, st state) {
	obj, field, weak, ok := a.pathOf(lhs)
	if !ok {
		a.eval(lhs, st)
		return
	}
	if inert(obj.Type()) && field == "" {
		t = nil
	}
	if ty := a.info.TypeOf(lhs); inert(ty) {
		t = nil
	}
	if isGlobal(obj) {
		var src taintSet
		for _, at := range t {
			if at.param < 0 {
				src = append(src, at)
			}
		}
		a.globals[obj] = merge(a.globals[obj], src)
	}
	st.write(obj, field, t, weak)
}

func (a *analyzer) stmt(s ast.Stmt, st state) {
	switch s := s.(type) {
	case *ast.ExprStmt:
		a.eval(s.X, st)
	case *ast.AssignStmt:
		a.assignStmt(s, st)
	case *ast.DeclStmt:
		gd, ok := s.Decl.(*ast.GenDecl)
		if !ok {
			return
		}
		for _, sp := range gd.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if len(vs.Values) == 1 && len(vs.Names) > 1 {
				t := a.eval(vs.Values[0], st)
				for _, n := range vs.Names {
					a.assign(n, t, st)
				}
				continue
			}
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					a.assign(n, a.eval(vs.Values[i], st), st)
				}
			}
		}
	case *ast.BlockStmt:
		a.block(s.List, st)
	case *ast.IfStmt:
		a.stmt2(s.Init, st)
		a.eval(s.Cond, st)
		then := st.clone()
		a.markValid(a.validWhenTrue(s.Cond), then)
		a.block(s.Body.List, then)
		els := st.clone()
		a.markValid(a.validWhenFalse(s.Cond), els)
		elseEnds := false
		if s.Else != nil {
			a.stmt(s.Else, els)
			if b, ok := s.Else.(*ast.BlockStmt); ok {
				elseEnds = terminates(b.List)
			}
		}
		switch thenEnds := terminates(s.Body.List); {
		case thenEnds && !elseEnds:
			st.replace(els, els)
		case elseEnds && !thenEnds:
			st.replace(then, then)
		default:
			st.replace(then, els)
		}
	case *ast.BranchStmt:
		if (s.Tok == token.BREAK || s.Tok == token.CONTINUE) && a.ctx.loopAcc != nil {
			a.ctx.loopAcc.union(st)
		}
	case *ast.ForStmt:
		a.stmt2(s.Init, st)
		prev := a.ctx.loopAcc
		a.ctx.loopAcc = state{}
		for range 2 {
			a.eval(s.Cond, st)
			body := st.clone()
			a.block(s.Body.List, body)
			a.stmt2(s.Post, body)
			st.union(body)
		}
		st.union(a.ctx.loopAcc)
		a.ctx.loopAcc = prev
	case *ast.RangeStmt:
		t := a.eval(s.X, st)
		prev := a.ctx.loopAcc
		a.ctx.loopAcc = state{}
		for range 2 {
			body := st.clone()
			if s.Key != nil {
				a.assign(s.Key, t, body)
			}
			if s.Value != nil {
				a.assign(s.Value, t, body)
			}
			a.block(s.Body.List, body)
			st.union(body)
		}
		st.union(a.ctx.loopAcc)
		a.ctx.loopAcc = prev
	case *ast.SwitchStmt:
		a.stmt2(s.Init, st)
		a.eval(s.Tag, st)
		a.clauses(s.Body, st)
	case *ast.TypeSwitchStmt:
		a.stmt2(s.Init, st)
		a.typeSwitch(s, st)
	case *ast.SelectStmt:
		a.clauses(s.Body, st)
	case *ast.ReturnStmt:
		for _, r := range s.Results {
			t := a.eval(r, st)
			if a.ctx.litDeep == 0 {
				a.ctx.ret = merge(a.ctx.ret, t)
			}
		}
	case *ast.DeferStmt:
		a.eval(s.Call, st)
	case *ast.GoStmt:
		a.eval(s.Call, st)
	case *ast.SendStmt:
		a.eval(s.Value, st)
	case *ast.IncDecStmt:
		a.eval(s.X, st)
	case *ast.LabeledStmt:
		a.stmt(s.Stmt, st)
	case *ast.CaseClause:
		for _, x := range s.Body {
			a.stmt(x, st)
		}
	case *ast.CommClause:
		a.stmt2(s.Comm, st)
		for _, x := range s.Body {
			a.stmt(x, st)
		}
	}
}

func (a *analyzer) stmt2(s ast.Stmt, st state) {
	if s != nil {
		a.stmt(s, st)
	}
}

func (a *analyzer) block(list []ast.Stmt, st state) {
	for _, s := range list {
		a.stmt(s, st)
	}
}

// clauses runs each switch/select clause from the same entry state and merges the
// results, together with the entry state itself (no clause may run).
func (a *analyzer) clauses(body *ast.BlockStmt, st state) {
	entry := st.clone()
	for _, cl := range body.List {
		branch := entry.clone()
		switch cl := cl.(type) {
		case *ast.CaseClause:
			for _, x := range cl.List {
				a.eval(x, branch)
			}
			a.block(cl.Body, branch)
		case *ast.CommClause:
			a.stmt2(cl.Comm, branch)
			a.block(cl.Body, branch)
		}
		st.union(branch)
	}
}

// typeSwitch seeds the per-clause variable of "switch v := x.(type)" with the taint of x.
func (a *analyzer) typeSwitch(s *ast.TypeSwitchStmt, st state) {
	var t taintSet
	switch as := s.Assign.(type) {
	case *ast.AssignStmt:
		if len(as.Rhs) == 1 {
			t = a.eval(as.Rhs[0], st)
		}
	case *ast.ExprStmt:
		a.eval(as.X, st)
	}
	entry := st.clone()
	for _, cl := range s.Body.List {
		cc := cl.(*ast.CaseClause)
		branch := entry.clone()
		if v, ok := a.info.Implicits[cc].(*types.Var); ok && !inert(v.Type()) {
			branch.write(v, "", t, false)
		}
		a.block(cc.Body, branch)
		st.union(branch)
	}
}

// noteCleaned records which variables now hold a cleaned path.
func (a *analyzer) noteCleaned(s *ast.AssignStmt) {
	if len(s.Lhs) != len(s.Rhs) {
		return
	}
	for i, l := range s.Lhs {
		obj, _, _, ok := a.pathOf(l)
		if !ok {
			continue
		}
		cleaned := false
		if c, isCall := unparen(s.Rhs[i]).(*ast.CallExpr); isCall {
			switch name, _ := a.calleeName(c.Fun); name {
			case "path/filepath.Join", "path/filepath.Clean", "path/filepath.Abs", "path.Join", "path.Clean":
				cleaned = true
			}
		}
		if cleaned {
			a.ctx.cleaned[obj] = true
		} else {
			delete(a.ctx.cleaned, obj)
		}
	}
}

func (a *analyzer) assignStmt(s *ast.AssignStmt, st state) {
	defer a.noteCleaned(s)
	a.noteOK(s)
	if len(s.Rhs) == 1 && len(s.Lhs) > 1 {
		t := a.eval(s.Rhs[0], st)
		for _, l := range s.Lhs {
			a.assign(l, t, st)
		}
		return
	}
	vals := make([]taintSet, len(s.Rhs))
	for i, r := range s.Rhs {
		vals[i] = a.eval(r, st)
	}
	for i, l := range s.Lhs {
		if i >= len(vals) {
			break
		}
		t := vals[i]
		if s.Tok != token.ASSIGN && s.Tok != token.DEFINE {
			// x += y keeps what x already held.
			t = merge(a.eval(l, st), t)
		}
		a.assign(l, t, st)
	}
}

// analyzeFunc computes the summary of one declared function and reports findings.
func (a *analyzer) analyzeFunc(fd *ast.FuncDecl, name string) *summary {
	a.ctx = &funcCtx{name: name, label: declName(fd)}
	st := state{}
	a.ctx.oks = map[types.Object]ast.Expr{}
	a.ctx.cleaned = map[types.Object]bool{}
	if fd.Recv != nil && len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
		if o, ok := a.info.Defs[fd.Recv.List[0].Names[0]].(*types.Var); ok && o.Name() != "_" {
			st[vkey{o, ""}] = taintSet{{key: "pr", param: recvParam, kinds: kAll}}
		}
	}
	i := 0
	for _, f := range fd.Type.Params.List {
		for _, n := range f.Names {
			if o, ok := a.info.Defs[n].(*types.Var); ok && n.Name != "_" && !inert(o.Type()) {
				st[vkey{o, ""}] = taintSet{{key: fmt.Sprintf("p%d", i), param: i, kinds: kAll}}
			}
			i++
		}
		if len(f.Names) == 0 {
			i++
		}
	}
	a.block(fd.Body.List, st)
	sum := &summary{ret: a.ctx.ret}
	seen := map[string]bool{}
	for _, k := range a.ctx.sinks {
		id := fmt.Sprintf("%d|%d|%s|%d", k.param, k.kind, k.name, k.pos)
		if !seen[id] {
			seen[id] = true
			sum.sinks = append(sum.sinks, k)
		}
	}
	sort.Slice(sum.sinks, func(i, j int) bool {
		x, y := sum.sinks[i], sum.sinks[j]
		if x.param != y.param {
			return x.param < y.param
		}
		if x.pos != y.pos {
			return x.pos < y.pos
		}
		return x.name < y.name
	})
	return sum
}

// declName is the name used in subjects: "F" for a function, "T.M" for a method.
func declName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + fd.Name.Name
		}
		return fd.Name.Name
	}
}

// signature identifies the shared analysis state, so a fixed point can be detected.
func (sh *shared) signature() string {
	keys := make([]string, 0, len(sh.sums))
	for k := range sh.sums {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s{%s}", k, sh.sums[k].signature())
	}
	gl := make([]string, 0, len(sh.globals))
	for o, t := range sh.globals {
		var g strings.Builder
		fmt.Fprintf(&g, "%s.%d", o.Name(), o.Pos())
		for _, at := range t {
			fmt.Fprintf(&g, ":%s/%d", at.key, at.kinds)
		}
		gl = append(gl, g.String())
	}
	sort.Strings(gl)
	return b.String() + strings.Join(gl, ";")
}

// safely runs analyzeFunc and reports whether it completed.
func (a *analyzer) safely(fd *ast.FuncDecl, name string) (sum *summary, ok bool) {
	defer func() {
		if recover() != nil {
			sum, ok = nil, false
		}
	}()
	return a.analyzeFunc(fd, name), true
}
