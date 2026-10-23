package sast

import (
	"fmt"
	"go/token"
	"path"
	"slices"
	"sort"
	"strings"
)

// langSpec is the security model of one language: where untrusted data enters, which
// calls are dangerous, and which neutralize what.
type langSpec struct {
	name string
	// sinks and sanitizers are keyed by qualified name ("child_process.exec",
	// "java.sql.Statement.executeQuery"). A key "?.query" matches a method of that name
	// on a receiver whose type is not known.
	sinks      map[string]sink
	sanitizers map[string]kind
	// sourcePrefixes: any value reached through a qualified name with one of these
	// prefixes is untrusted ("flask.request" covers request.args.get(...)).
	sourcePrefixes map[string]string
	// sourceRoots: variable name -> member -> description. The member "*" matches any
	// member or index: req.query, $_GET["id"], params[:id].
	sourceRoots map[string]map[string]string
	// sourceMethods are method names that read request data from any receiver:
	// getParameter, get_argument.
	sourceMethods map[string]string
	// returns maps a qualified call to the type it returns, so a chain such as
	// conn.createStatement().executeQuery(..) resolves to a known method.
	returns map[string]string
	// self names the receiver inside a method.
	self map[string]bool
	// shells are executables that parse their argument as a command line.
	shells map[string]bool
	// assignSinks are members that are dangerous to assign to: el.innerHTML = x.
	assignSinks map[string]kind
	// mutators are methods that add their arguments to the receiver: sb.append(x),
	// list.push(x). The receiver then holds the argument's taint.
	mutators map[string]bool
	// simpleTypes maps a class name usable without an import (java.lang, or a wildcard
	// import) to its qualified name.
	simpleTypes map[string]string
	// misuse and assignMisuse list unsafe calls and assignments that need no tainted data.
	misuse       map[string][]misuse
	assignMisuse map[string]assignMisuse
	// builtins are global functions that may be named without an import.
	builtins map[string]bool
}

type ikey struct{ name, field string }

type istate map[ikey]taintSet

func (s istate) clone() istate {
	out := make(istate, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

func (s istate) union(o istate) {
	for k, v := range o {
		s[k] = merge(s[k], v)
	}
}

func (s istate) replace(a, b istate) {
	clear(s)
	s.union(a)
	s.union(b)
}

func (s istate) read(name, field string) taintSet {
	var out taintSet
	for k, v := range s {
		if k.name == name && related(k.field, field) {
			out = merge(out, v)
		}
	}
	return out
}

func (s istate) has(name string) bool {
	for k := range s {
		if k.name == name {
			return true
		}
	}
	return false
}

func (s istate) write(name, field string, t taintSet, weak bool) {
	if !weak {
		for k := range s {
			if k.name == name && (k.field == field || strings.HasPrefix(k.field, field+".")) {
				delete(s, k)
			}
		}
	}
	if len(t) > 0 {
		k := ikey{name, field}
		s[k] = merge(s[k], t)
	}
}

// project is the set of lowered files an analysis can resolve imports between.
type project struct {
	mods    map[string]*module // by path
	classes map[string]string  // class name -> path of the module defining it
	// methods maps "Class.method" to the key of its summary.
	methods map[string][]string
	// byName maps a bare method name to every class method with it, for calls on a value
	// whose class is not known.
	byName map[string][]string
}

func funcKey(m *module, f *funcIR) string {
	if f.class != "" {
		return m.path + "#" + f.class + "." + f.name
	}
	return m.path + "#" + f.name
}

func newProject(mods []*module) *project {
	p := &project{mods: map[string]*module{}, classes: map[string]string{}, methods: map[string][]string{}, byName: map[string][]string{}}
	for _, m := range mods {
		p.mods[m.path] = m
		for _, f := range m.funcs {
			if f.class == "" {
				continue
			}
			p.classes[f.class] = m.path
			key := funcKey(m, f)
			p.methods[f.class+"."+f.name] = append(p.methods[f.class+"."+f.name], key)
			if f.name != "<init>" {
				p.byName[f.name] = append(p.byName[f.name], key)
			}
			// A call through a supertype may run any subclass's override.
			for _, sup := range m.supers[f.class] {
				p.methods[sup+"."+f.name] = append(p.methods[sup+"."+f.name], key)
			}
		}
	}
	return p
}

// resolveModule finds the project file a local import refers to.
func (p *project) resolveModule(from *module, spec string) *module {
	dir := path.Dir(from.path)
	var cands []string
	switch from.lang {
	case "js", "ts":
		if !strings.HasPrefix(spec, ".") {
			return nil
		}
		base := path.Join(dir, spec)
		for _, ext := range []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"} {
			cands = append(cands, base+ext, path.Join(base, "index"+ext))
		}
		// "./db.js" in TypeScript source may stand for db.ts.
		if ext := path.Ext(base); ext == ".js" || ext == ".jsx" {
			stem := strings.TrimSuffix(base, ext)
			cands = append(cands, stem+".ts", stem+".tsx")
		}
		cands = append(cands, base)
	case "py":
		rel := spec
		lead := 0
		for lead < len(rel) && rel[lead] == '.' {
			lead++
		}
		mod := strings.ReplaceAll(rel[lead:], ".", "/")
		if lead > 0 {
			d := dir
			for i := 1; i < lead; i++ {
				d = path.Dir(d)
			}
			cands = append(cands, path.Join(d, mod)+".py", path.Join(d, mod, "__init__.py"))
		} else {
			cands = append(cands, path.Join(dir, mod)+".py", mod+".py", path.Join(mod, "__init__.py"))
		}
	case "rb":
		cands = append(cands, path.Join(dir, spec)+".rb", spec+".rb")
	case "php":
		cands = append(cands, path.Join(dir, spec), spec)
	}
	for _, c := range cands {
		if m, ok := p.mods[path.Clean(c)]; ok {
			return m
		}
	}
	return nil
}

// irRun analyzes the functions of one module.
type irRun struct {
	*analyzer
	spec  *langSpec
	proj  *project
	mod   *module
	class string
	types map[string]string
	// shadow marks names assigned in the function, so a local called "params" is not
	// mistaken for the request parameters.
	shadow map[string]bool
}

// maxNameCandidates bounds the name-based guess for a call on a value of unknown class.
const maxNameCandidates = 3

// recvName is the state key under which a method's receiver is kept.
const recvName = "\x00self"

func (r *irRun) selfName(e *expr) bool {
	return e != nil && e.kind == exprName && r.spec.self[e.name]
}

// pathOf resolves a chain of member accesses on a name to a state key.
func (r *irRun) pathOf(e *expr) (name, field string, ok bool) {
	switch e.kind {
	case exprName:
		if r.spec.self[e.name] {
			return recvName, "", true
		}
		return e.name, "", true
	case exprMember:
		if n, f, ok := r.pathOf(e.x); ok {
			return n, f + "." + e.name, true
		}
	}
	return "", "", false
}

// qualified returns the dotted qualified name of an expression that names a module,
// function or global, or "" when it is a plain variable.
func (r *irRun) qualified(e *expr, st istate) string {
	switch e.kind {
	case exprName:
		if q, ok := r.mod.imports[e.name]; ok {
			return q
		}
		if _, ok := r.mod.locals[e.name]; ok {
			return ""
		}
		if st.has(e.name) || r.types[e.name] != "" {
			return ""
		}
		if q, ok := r.spec.simpleTypes[e.name]; ok {
			return q
		}
		if r.spec.builtins[e.name] {
			return e.name
		}
	case exprMember:
		if q := r.qualified(e.x, st); q != "" {
			return q + "." + e.name
		}
	}
	return ""
}

// typeOf is the qualified or project-local type of an expression, when known.
func (r *irRun) typeOf(e *expr, st istate) string {
	switch e.kind {
	case exprName:
		if t, ok := r.types[e.name]; ok {
			return t
		}
		if r.class != "" {
			if t, ok := r.mod.fieldType(r.class, e.name); ok {
				return t
			}
		}
	case exprMember:
		if r.selfName(e.x) && r.class != "" {
			if t, ok := r.mod.fieldType(r.class, e.name); ok {
				return t
			}
		}
	case exprNew:
		if q := r.qualified(e.x, st); q != "" {
			return q
		}
		if e.x.kind == exprName {
			return e.x.name
		}
	case exprCall:
		if q, _, _ := r.resolve(e.x, st); q != "" {
			if t, ok := r.spec.returns[q]; ok {
				return t
			}
		}
		if e.x.kind == exprName {
			if _, ok := r.proj.classes[e.x.name]; ok {
				return e.x.name
			}
		}
	}
	return ""
}

func (m *module) fieldType(class, name string) (string, bool) {
	t, ok := m.fields[class][name]
	return t, ok
}

// resolve names the callee: its qualified name, the receiver expression for a method
// call, and the member name.
func (r *irRun) resolve(fn *expr, st istate) (qname string, recv *expr, field string) {
	switch fn.kind {
	case exprName:
		return r.qualified(fn, st), nil, ""
	case exprMember:
		if q := r.qualified(fn, st); q != "" {
			return q, nil, fn.name
		}
		if t := r.typeOf(fn.x, st); t != "" {
			return r.resolveType(t) + "." + fn.name, fn.x, fn.name
		}
		return "?." + fn.name, fn.x, fn.name
	}
	return "", nil, ""
}

func (r *irRun) eval(e *expr, st istate) taintSet {
	if e == nil {
		return nil
	}
	switch e.kind {
	case exprStr, exprNum:
		return nil
	case exprName:
		if desc, ok := r.spec.sourceRoots[e.name]["*"]; ok && !r.shadow[e.name] {
			return r.source(e.pos, desc)
		}
		if name, f, ok := r.pathOf(e); ok {
			return st.read(name, f)
		}
	case exprMember:
		return r.evalMember(e, st)
	case exprIndex:
		for _, a := range e.args {
			r.eval(a, st)
		}
		if e.x.kind == exprName {
			if desc, ok := r.spec.sourceRoots[e.x.name]["*"]; ok && !r.shadow[e.x.name] {
				return r.source(e.pos, desc)
			}
		}
		return r.eval(e.x, st)
	case exprCall, exprNew:
		return r.evalCall(e, st)
	case exprConcat, exprOther:
		out := r.eval(e.x, st)
		for _, a := range e.args {
			out = merge(out, r.eval(a, st))
		}
		return out
	case exprLambda:
		r.walkFn(e.fn, st, nil)
	case exprNot:
		r.eval(e.x, st)
	case exprAnd, exprOr, exprIn:
		r.eval(e.x, st)
		for _, a := range e.args {
			r.eval(a, st)
		}
	}
	return nil
}

func (r *irRun) evalMember(e *expr, st istate) taintSet {
	if q := r.qualified(e, st); q != "" {
		if desc, ok := r.sourceByPrefix(q); ok {
			return r.source(e.pos, desc)
		}
	}
	if e.x.kind == exprName && !r.shadow[e.x.name] {
		if desc, ok := r.spec.sourceRoots[e.x.name][e.name]; ok {
			return r.source(e.pos, desc)
		}
		if desc, ok := r.spec.sourceRoots[e.x.name]["*"]; ok {
			return r.source(e.pos, desc)
		}
	}
	if name, f, ok := r.pathOf(e); ok {
		t := st.read(name, f)
		// A source member anywhere along the chain taints everything beneath it.
		for x := e; x != nil && x.kind == exprMember; x = x.x {
			if x.x.kind == exprName {
				if desc, ok := r.spec.sourceRoots[x.x.name][x.name]; ok && !r.shadow[x.x.name] {
					t = merge(t, r.source(x.pos, desc))
				}
			}
		}
		return t
	}
	return r.eval(e.x, st)
}

func (r *irRun) sourceByPrefix(q string) (string, bool) {
	for p, d := range r.spec.sourcePrefixes {
		if q == p || strings.HasPrefix(q, p+".") {
			return d, true
		}
	}
	return "", false
}

func (r *irRun) evalCall(e *expr, st istate) taintSet {
	args := make([]taintSet, len(e.args))
	for i, a := range e.args {
		args[i] = r.eval(a, st)
	}
	fn := e.x
	qname, recvExpr, field := r.resolve(fn, st)
	var recvT taintSet
	switch {
	case recvExpr != nil:
		recvT = r.eval(recvExpr, st)
	case fn.kind == exprMember:
		recvT = r.eval(fn.x, st)
	case fn.kind != exprName:
		recvT = r.eval(fn, st)
	}

	if s, name, ok := r.lookupSink(qname, recvExpr, field); ok {
		r.checkSink(e, name, s, args, recvT)
	}
	r.checkMisuse(e, qname, field)
	if fn.kind == exprMember && r.spec.mutators[fn.name] {
		var added taintSet
		for _, t := range args {
			added = merge(added, t)
		}
		if name, f, ok := r.pathOf(fn.x); ok {
			st.write(name, f, added, true)
		}
	}
	if desc, ok := r.callSource(fn); ok {
		return r.source(e.pos, desc)
	}
	if qname != "" {
		if desc, ok := r.sourceByPrefix(qname); ok {
			return r.source(e.pos, desc)
		}
	}
	all := recvT
	for _, t := range args {
		all = merge(all, t)
	}
	if k, ok := r.spec.sanitizers[qname]; ok {
		return all.clear(k)
	}
	if k, ok := r.spec.sanitizers["?."+field]; ok && field != "" && recvExpr != nil {
		return all.clear(k)
	}
	if s, _, ok := r.lookupSink(qname, recvExpr, field); ok && s.kind != kXSS {
		// What a query or file read returns is not the payload that was passed in.
		return nil
	}
	if keys := r.targets(fn, e, st); len(keys) > 0 {
		var out taintSet
		for _, key := range keys {
			if sum, ok := r.sums[key]; ok {
				out = merge(out, r.applyIR(e, key, sum, args, recvT))
			}
		}
		return out
	}
	return all
}

// lookupSink finds the sink for a call: by qualified name, else by method name on any
// receiver the sink admits.
func (r *irRun) lookupSink(qname string, recv *expr, field string) (sink, string, bool) {
	if s, ok := r.spec.sinks[qname]; ok && !strings.HasPrefix(qname, "?.") {
		return s, qname, true
	}
	if recv == nil || field == "" {
		return sink{}, "", false
	}
	s, ok := r.spec.sinks["?."+field]
	if !ok {
		return sink{}, "", false
	}
	if len(s.recv) > 0 && !slices.Contains(s.recv, rootName(recv)) {
		return sink{}, "", false
	}
	return s, "." + field, true
}

// rootName is the variable at the base of a chain of member accesses and calls.
func rootName(e *expr) string {
	for e != nil {
		switch e.kind {
		case exprName:
			return e.name
		case exprMember, exprIndex, exprCall:
			e = e.x
		default:
			return ""
		}
	}
	return ""
}

// callSource reports a call such as req.get("Referer") on a request object.
func (r *irRun) callSource(fn *expr) (string, bool) {
	if fn.kind != exprMember {
		return "", false
	}
	if fn.x.kind == exprName && !r.shadow[fn.x.name] {
		if d, ok := r.spec.sourceRoots[fn.x.name][fn.name]; ok {
			return d, true
		}
	}
	d, ok := r.spec.sourceMethods[fn.name]
	return d, ok
}

// targets are the summary keys of the project functions a call may reach.
func (r *irRun) targets(fn, call *expr, st istate) []string {
	var keys []string
	add := func(m *module, class, name string) {
		for _, f := range m.funcs {
			if f.name == name && f.class == class {
				keys = append(keys, funcKey(m, f))
				return
			}
		}
	}
	switch fn.kind {
	case exprName:
		if r.class != "" {
			// A bare call inside a class may be a call to one of its methods.
			add(r.mod, r.class, fn.name)
		}
		add(r.mod, "", fn.name)
		if len(keys) == 0 {
			if ref, ok := r.mod.locals[fn.name]; ok && ref.name != "" {
				if m := r.proj.resolveModule(r.mod, ref.spec); m != nil {
					add(m, "", ref.name)
				}
			}
		}
		// A constructor call runs the class's constructor.
		if len(keys) == 0 && (call.kind == exprNew || r.proj.classes[fn.name] != "") {
			keys = append(keys, r.proj.methods[fn.name+".<init>"]...)
		}
	case exprMember:
		if r.selfName(fn.x) && r.class != "" {
			add(r.mod, r.class, fn.name)
			if len(keys) == 0 {
				keys = append(keys, r.proj.methods[r.class+"."+fn.name]...)
			}
			return keys
		}
		if fn.x.kind == exprName {
			if ref, ok := r.mod.locals[fn.x.name]; ok {
				spec := ref.spec
				if ref.name != "" && r.mod.lang == "py" {
					// from pkg import mod: the name may be a module.
					spec = strings.TrimSuffix(spec, ".") + "." + ref.name
					if strings.HasPrefix(ref.spec, ".") && !strings.HasSuffix(ref.spec, ".") {
						spec = ref.spec + "." + ref.name
					} else if strings.HasSuffix(ref.spec, ".") {
						spec = ref.spec + ref.name
					}
				} else if ref.name != "" {
					spec = ""
				}
				if spec != "" {
					if m := r.proj.resolveModule(r.mod, spec); m != nil {
						add(m, "", fn.name)
						return keys
					}
				}
			}
		}
		if t := r.typeOf(fn.x, st); t != "" {
			keys = append(keys, r.proj.methods[t+"."+fn.name]...)
		} else if cands := r.proj.byName[fn.name]; len(cands) > 0 && len(cands) <= maxNameCandidates {
			// The receiver's class is unknown. A method name that only a few classes
			// define is a good enough guess; a common name like get or find would not be.
			keys = append(keys, cands...)
		}
	}
	return keys
}

func (r *irRun) applyIR(c *expr, key string, sum *summary, args []taintSet, recvT taintSet) taintSet {
	np := 0
	if f := r.funcByKey(key); f != nil {
		np = len(f.params)
	}
	argAt := func(p int) taintSet {
		if p == recvParam {
			return recvT
		}
		var out taintSet
		for j, t := range args {
			// Keyword arguments are matched by position, which is the common case for the
			// small set of helpers the analysis follows.
			if j == p || (np > 0 && j >= np && p == np-1) {
				out = merge(out, t)
			}
		}
		return out
	}
	callStep := "passed to " + shortName(key[strings.LastIndex(key, "#")+1:])
	for _, sk := range sum.sinks {
		for _, at := range argAt(sk.param) {
			if hit := at.kinds & sk.kind; hit != 0 {
				at.flow = &flow{pos: c.pos, msg: callStep, prev: at.flow}
				r.reachSink(sk.pos, sk.name, hit, at, sk.flow)
			}
		}
	}
	var out taintSet
	for _, rt := range sum.ret {
		if rt.param < 0 {
			out = merge(out, taintSet{{key: rt.key, param: -1, kinds: rt.kinds, flow: &flow{pos: c.pos, msg: "returned by " + callStep[len("passed to "):], prev: rt.flow}}})
			continue
		}
		out = merge(out, argAt(rt.param).clear(^rt.kinds).step(c.pos, "flows through "+callStep[len("passed to "):]))
	}
	return out
}

func (r *irRun) funcByKey(key string) *funcIR {
	file, _, _ := strings.Cut(key, "#")
	m := r.proj.mods[file]
	if m == nil {
		return nil
	}
	for _, f := range m.funcs {
		if funcKey(m, f) == key {
			return f
		}
	}
	return nil
}

func (r *irRun) checkSink(c *expr, name string, s sink, args []taintSet, recv taintSet) {
	if s.solo && len(c.args) != 1 {
		return
	}
	if s.kwTrue != "" {
		ok := false
		for i, k := range c.kw {
			if k == s.kwTrue && c.args[i].kind == exprNum && (c.args[i].str == "True" || c.args[i].str == "true") {
				ok = true
			}
		}
		if !ok {
			return
		}
	}
	idx := slices.Clone(s.args)
	if s.rest {
		for i := s.args[len(s.args)-1] + 1; i < len(args); i++ {
			idx = append(idx, i)
		}
	}
	if s.shellFrom > 0 && len(s.args) > 0 && s.args[0] < len(c.args) {
		if a := c.args[s.args[0]]; a.kind == exprStr && r.spec.shells[a.str] {
			for i := s.shellFrom; i < len(args); i++ {
				idx = append(idx, i)
			}
		}
	}
	for _, i := range idx {
		if i == -1 {
			for _, at := range recv {
				if hit := at.kinds & s.kind; hit != 0 {
					r.reachSink(c.pos, name, hit, at, nil)
				}
			}
			continue
		}
		if i >= len(args) || (i < len(c.kw) && c.kw[i] != "" && s.kwTrue == "") {
			continue
		}
		if s.strArg && c.args[i].kind == exprOther {
			continue
		}
		for _, at := range args[i] {
			if hit := at.kinds & s.kind; hit != 0 {
				r.reachSink(c.pos, name, hit, at, nil)
			}
		}
	}
}

func (r *irRun) assign(lhs *expr, t taintSet, st istate) {
	switch lhs.kind {
	case exprName, exprMember:
		name, f, ok := r.pathOf(lhs)
		if !ok {
			r.eval(lhs, st)
			return
		}
		st.write(name, f, t, false)
	case exprIndex:
		if name, f, ok := r.pathOf(lhs.x); ok {
			st.write(name, f, t, true)
		}
	default:
		r.eval(lhs, st)
	}
}

func (r *irRun) block(list []*stmt, st istate) {
	for _, s := range list {
		r.stmt(s, st)
	}
}

func terminatesIR(list []*stmt) bool {
	if len(list) == 0 {
		return false
	}
	switch s := list[len(list)-1]; s.kind {
	case stmtReturn, stmtJump:
		return true
	case stmtIf:
		return terminatesIR(s.then) && terminatesIR(s.els)
	}
	return false
}

func (r *irRun) validWhenTrue(c *expr) []*expr {
	switch c.kind {
	case exprAnd:
		return append(r.validWhenTrue(c.args[0]), r.validWhenTrue(c.args[1])...)
	case exprIn:
		return []*expr{c.args[0]}
	}
	return nil
}

func (r *irRun) validWhenFalse(c *expr) []*expr {
	switch c.kind {
	case exprNot:
		return r.validWhenTrue(c.x)
	case exprOr:
		return append(r.validWhenFalse(c.args[0]), r.validWhenFalse(c.args[1])...)
	}
	return nil
}

func (r *irRun) markValid(vals []*expr, st istate) {
	for _, v := range vals {
		if name, f, ok := r.pathOf(v); ok {
			st.write(name, f, nil, false)
		}
	}
}

func (r *irRun) stmt(s *stmt, st istate) {
	switch s.kind {
	case stmtExpr:
		r.eval(s.rhs, st)
	case stmtAssign:
		t := r.eval(s.rhs, st)
		for _, l := range s.lhs {
			v := t
			if s.aug {
				v = merge(r.eval(l, st), t)
			}
			r.assign(l, v, st)
			r.checkAssignMisuse(l, s.rhs)
			if l.kind == exprName {
				r.shadow[l.name] = true
			}
			if l.kind == exprMember {
				if k, ok := r.spec.assignSinks[l.name]; ok {
					for _, at := range t {
						if hit := at.kinds & k; hit != 0 {
							r.reachSink(l.pos, "."+l.name, hit, at, nil)
						}
					}
				}
			}
			if l.kind == exprName && s.rhs != nil {
				if l.ty != "" {
					r.types[l.name] = r.resolveType(l.ty)
				} else if ty := r.typeOf(s.rhs, st); ty != "" {
					r.types[l.name] = ty
				} else {
					delete(r.types, l.name)
				}
			}
		}
	case stmtReturn:
		t := r.eval(s.rhs, st)
		if r.ctx.litDeep == 0 {
			r.ctx.ret = merge(r.ctx.ret, t)
		}
	case stmtJump:
		r.eval(s.rhs, st)
	case stmtIf:
		r.eval(s.cond, st)
		then := st.clone()
		if s.cond != nil {
			r.markValid(r.validWhenTrue(s.cond), then)
		}
		r.block(s.then, then)
		els := st.clone()
		if s.cond != nil {
			r.markValid(r.validWhenFalse(s.cond), els)
		}
		r.block(s.els, els)
		switch thenEnds, elseEnds := terminatesIR(s.then), terminatesIR(s.els); {
		case thenEnds && !elseEnds:
			st.replace(els, els)
		case elseEnds && !thenEnds:
			st.replace(then, then)
		default:
			st.replace(then, els)
		}
	case stmtLoop:
		t := r.eval(s.rhs, st)
		for range 2 {
			body := st.clone()
			for _, l := range s.lhs {
				r.assign(l, t, body)
			}
			r.block(s.then, body)
			st.union(body)
		}
	case stmtBranch:
		entry := st.clone()
		for _, arm := range s.arms {
			b := entry.clone()
			r.block(arm, b)
			st.union(b)
		}
	}
}

func (r *irRun) resolveType(t string) string {
	if q, ok := r.mod.imports[t]; ok {
		return q
	}
	if q, ok := r.spec.simpleTypes[t]; ok {
		return q
	}
	return t
}

// walkFn analyzes a function expression in place, sharing the enclosing state.
func (r *irRun) walkFn(f *funcIR, st istate, args []taintSet) {
	inner := st.clone()
	for i, p := range f.params {
		if i < len(args) && len(args[i]) > 0 {
			inner.write(p.name, "", args[i], false)
		}
	}
	r.ctx.litDeep++
	r.block(f.body, inner)
	r.ctx.litDeep--
	st.union(inner)
}

func isNumericType(t string) bool {
	switch strings.ToLower(t) {
	case "int", "integer", "long", "short", "byte", "float", "double", "boolean", "bool", "number", "uint", "int32", "int64", "float32", "float64":
		return true
	}
	return false
}

// analyze computes the summary of one function and reports findings.
func (r *irRun) analyze(f *funcIR) *summary {
	key := funcKey(r.mod, f)
	r.ctx = &funcCtx{name: key, label: f.name}
	if f.class != "" {
		r.ctx.label = f.class + "." + f.name
	}
	r.class = f.class
	r.types = map[string]string{}
	r.shadow = map[string]bool{}
	st := istate{}
	if f.class != "" {
		st[ikey{recvName, ""}] = taintSet{{key: "pr", param: recvParam, kinds: kAll}}
	}
	for i, p := range f.params {
		if p.ty != "" {
			r.types[p.name] = r.resolveType(p.ty)
		}
		if isNumericType(p.ty) {
			continue
		}
		t := taintSet{{key: fmt.Sprintf("p%d", i), param: i, kinds: kAll}}
		if p.source != "" {
			t = merge(t, r.source(f.pos, p.source))
		}
		st[ikey{p.name, ""}] = t
	}
	r.block(f.body, st)
	sum := &summary{ret: r.ctx.ret}
	seen := map[string]bool{}
	for _, k := range r.ctx.sinks {
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

// safely runs analyze and reports whether it completed.
func (r *irRun) safely(f *funcIR) (sum *summary, ok bool) {
	defer func() {
		if recover() != nil {
			sum, ok = nil, false
		}
	}()
	return r.analyze(f), true
}

// analyzeModule runs every function of a module, plus its top-level code, and returns
// the functions whose analysis failed.
func analyzeModule(sh *shared, spec *langSpec, proj *project, m *module, base *analyzer) (failed []token.Pos) {
	run := &irRun{analyzer: base, spec: spec, proj: proj, mod: m}
	run.langName = spec.name
	all := append([]*funcIR{{name: "<module>", body: m.top}}, m.funcs...)
	for _, f := range all {
		sum, ok := run.safely(f)
		if !ok {
			failed = append(failed, f.pos)
			continue
		}
		sh.sums[funcKey(m, f)] = sum
	}
	return failed
}
