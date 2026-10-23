package sast

import (
	"fmt"
	"go/token"
	"path"
	"regexp"
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
	// sourceMembers are attribute names that are untrusted on any receiver:
	// ZipInfo.filename.
	sourceMembers map[string]string
	// sourceVarMembers are members that are request data when read from a variable with
	// a telling name: txtUser.Text in ASP.NET WebForms.
	sourceVarMembers map[string]*regexp.Regexp
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
	// assignRoots are containers whose elements the application trusts or sends back:
	// session["k"] = value.
	assignRoots map[string]kind
	// nameSinks are variables that collect output the framework later writes to the
	// page, such as $html in PHP code that is included into a template.
	nameSinks map[string]kind
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
	// weakRNG are calls to a predictable random number generator.
	weakRNG map[string]bool
	// fsCheck and fsUse are file checks and destructive file operations, for TOCTOU.
	fsCheck, fsUse map[string]bool
	// xxeFactories create an XML parser that resolves external entities unless hardened.
	xxeFactories map[string]bool
	// cookieCtors create a cookie whose flags are set by later calls (Java's new Cookie).
	cookieCtors map[string]bool
	// pkgRoots are the first segments of fully qualified names written inline, as in
	// java.io.File or org.apache.commons.io.FileUtils.
	pkgRoots map[string]bool
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
		if isMarker(k.field) {
			continue
		}
		s[k] = merge(s[k], v)
	}
}

func (s istate) mark(name, field string, kinds kind) {
	k := ikey{name, markerPrefix + field}
	s[k] = merge(s[k], taintSet{{key: "valid", kinds: kinds}})
}

func (s istate) replace(a, b istate) {
	clear(s)
	s.union(a)
	s.union(b)
	// A value is validated after the branches only if it was validated in both.
	for k := range a {
		if isMarker(k.field) {
			if v, both := b[k]; both {
				s[k] = a[k].keep(markerKinds(v))
			}
		}
	}
}

func (s istate) read(name, field string) taintSet {
	var out taintSet
	for k, v := range s {
		if k.name == name && !isMetadata(k.field) && related(k.field, field) {
			out = merge(out, readField(v, k.field, field))
		}
	}
	return out.clear(s.validated(name, field))
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
	if field != "" {
		for _, peer := range s.aliases(name) {
			if peer != name {
				s.writeLocal(peer, field, t, true)
			}
		}
	}
	s.writeLocal(name, field, t, weak)
}

func (s istate) writeLocal(name, field string, t taintSet, weak bool) {
	s.invalidate(name, field)
	weak = weak || widenedField(field)
	if !weak {
		for k := range s {
			if k.name == name && !isMetadata(k.field) && (k.field == field || strings.HasPrefix(k.field, field+".")) {
				delete(s, k)
			}
		}
	}
	for _, at := range t {
		k := ikey{name, fieldJoin(field, at.path)}
		at.path = ""
		s[k] = merge(s[k], taintSet{at})
	}
}

// project is the set of lowered files an analysis can resolve imports between.
type project struct {
	mods      map[string]*module // by path
	classes   map[string]string  // class name -> path of the module defining it
	functions map[string]*funcIR // by summary key
	// methods maps "Class.method" to the key of its summary.
	methods map[string][]string
	// byName maps a bare method name to every class method with it, for calls on a value
	// whose class is not known.
	byName map[string][]string
	// props holds the key=value pairs of the project's .properties files.
	props map[string]string
	// globalCSRF is set when any file registers an antiforgery filter for every action.
	globalCSRF bool
}

func funcKey(m *module, f *funcIR) string {
	if f.class != "" {
		return m.path + "#" + f.class + "." + f.name
	}
	return m.path + "#" + f.name
}

func newProject(mods []*module) *project {
	p := &project{mods: map[string]*module{}, classes: map[string]string{}, functions: map[string]*funcIR{}, methods: map[string][]string{}, byName: map[string][]string{}}
	for _, m := range mods {
		p.mods[m.path] = m
		p.globalCSRF = p.globalCSRF || m.globalCSRF
		// A class with only constants has no methods but can still be named: Keys.JWT.
		for class := range m.fields {
			if p.classes[class] == "" {
				p.classes[class] = m.path
			}
		}
		for _, f := range m.funcs {
			if key := funcKey(m, f); p.functions[key] == nil {
				p.functions[key] = f
			}
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
	shadow     map[string]bool
	localNames map[string]bool
	cleanPaths map[string]bool
	boundaries map[string]bool
	// per-function state for the checks that look at order and context
	lhsName                      string
	loopAcc                      istate // states at break/continue in the innermost loop
	continueAcc                  istate
	fn                           *funcIR
	strVars                      map[string]bool   // variables that hold a string built in this function
	consts                       map[string]int64  // integer variables with a known value on this path
	strs                         map[string]string // string variables with a known value on this path
	devDepth                     int               // > 0 inside a branch that depends on the environment (IsDevelopment, NODE_ENV)
	checked                      map[string]bool
	xxeFactories                 []token.Pos
	xxeHardened                  bool
	cookies                      []token.Pos
	cookieSecure, cookieHTTPOnly bool
}

// commonMethods are names that the standard library defines on many types, so a project
// method of the same name says nothing about which one a call reaches.
var commonMethods = map[string]bool{
	"toString": true, "equals": true, "hashCode": true, "get": true, "set": true, "put": true, "add": true, "remove": true,
	"size": true, "length": true, "close": true, "run": true, "call": true, "apply": true, "accept": true, "compare": true,
	"valueOf": true, "getClass": true, "name": true, "value": true, "getValue": true, "getName": true, "contains": true,
	"isEmpty": true, "clear": true, "next": true, "print": true, "println": true, "write": true, "read": true, "of": true,
	"to_s": true, "to_a": true, "to_h": true, "each": true, "map": true, "join": true, "split": true, "append": true,
	"push": true, "pop": true, "keys": true, "values": true, "items": true,
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
	if e == nil {
		return "", "", false
	}
	switch e.kind {
	case exprName:
		if r.spec.self[e.name] {
			return recvName, "", true
		}
		if (r.spec.name == "java" || r.spec.name == "cs") && r.class != "" && !r.localNames[e.name] && !r.mod.staticFields[r.class+"."+e.name] {
			if _, ok := r.mod.fields[r.class][e.name]; ok {
				return recvName, fieldPart(e.name), true
			}
		}
		return e.name, "", true
	case exprMember:
		if n, f, ok := r.pathOf(e.x); ok {
			return n, fieldJoin(f, fieldPart(e.name)), true
		}
	case exprIndex:
		if len(e.args) == 1 {
			if part := constIndex(e.args[0]); part != "" {
				if n, f, ok := r.pathOf(e.x); ok {
					return n, fieldJoin(f, part), true
				}
			}
		}
	}
	return "", "", false
}

// qualified returns the dotted qualified name of an expression that names a module,
// function or global, or "" when it is a plain variable.
func (r *irRun) qualified(e *expr, st istate) string {
	if e == nil {
		return ""
	}
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
		if strings.Contains(e.name, ".") {
			return e.name // a type written out in full: new java.io.FileInputStream(...)
		}
		if r.spec.pkgRoots[e.name] && !st.has(e.name) && r.types[e.name] == "" {
			return e.name
		}
		if r.proj.functions[r.mod.path+"#"+e.name] != nil {
			return ""
		} // a project function shadows a library
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
	if e == nil {
		return ""
	}
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
		if r.spec.name == "rb" && e.x.kind == exprMember && e.x.name == "new" && e.x.x.kind == exprName && r.proj.classes[e.x.x.name] != "" {
			return e.x.x.name
		}
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
		if q := r.qualified(fn, st); q != "" {
			return q, nil, ""
		}
		if r.spec.name == "rb" {
			return "?." + fn.name, nil, fn.name
		}
		return "", nil, ""
	case exprMember:
		if q := r.qualified(fn, st); q != "" {
			// A qualified static call is also a call on its qualifier, so method-name
			// sinks (?.queryForObject) still apply to DatabaseHelper.template.query...().
			return q, fn.x, fn.name
		}
		if t := r.typeOf(fn.x, st); t != "" {
			return r.resolveType(t) + "." + fn.name, fn.x, fn.name
		}
		return "?." + fn.name, fn.x, fn.name
	}
	return "", nil, ""
}

func (r *irRun) eval(e *expr, st istate) (result taintSet) {
	if e == nil {
		return nil
	}
	if e.kind == exprName || e.kind == exprIndex {
		if name, field, ok := r.pathOf(e); ok {
			defer func() { result = result.clear(st.validated(name, field)) }()
		}
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
		if name, f, ok := r.pathOf(e); ok {
			// The base may itself be a source, whose taint is not stored in state.
			return merge(st.read(name, f), r.eval(e.x, st).selectField(constIndex(e.args[0])))
		}
		return r.eval(e.x, st)
	case exprCall, exprNew:
		return r.evalCall(e, st)
	case exprObject:
		var out taintSet
		for _, a := range e.args {
			out = merge(out, r.eval(a, st))
		}
		return out
	case exprField:
		return r.eval(e.x, st).atField(fieldPart(e.name))
	case exprConcat, exprOther:
		out := r.eval(e.x, st)
		for _, a := range e.args {
			out = merge(out, r.eval(a, st))
		}
		return out.scalar()
	case exprLambda:
		r.walkFn(e.fn, st, nil)
	case exprNot:
		r.eval(e.x, st)
	case exprBin:
		// Arithmetic and comparisons yield numbers and booleans, which cannot carry a
		// payload; the operands are still evaluated for the sinks inside them. A random
		// number stays random through arithmetic.
		var out taintSet
		for _, a := range e.args {
			out = merge(out, r.eval(a, st))
		}
		if isArith(e.str) {
			return out.keep(kRand)
		}
		return nil
	case exprCond:
		r.eval(e.x, st)
		if v, ok := r.constBool(e.x); ok {
			if v {
				return r.eval(e.args[0], st)
			}
			return r.eval(e.args[1], st)
		}
		return merge(r.eval(e.args[0], st), r.eval(e.args[1], st))
	case exprAnd, exprOr:
		// `a || b` and `a ?? b` evaluate to one of their operands, so they carry the
		// taint of both: const q = req.query.q || "" is still request data.
		out := r.eval(e.x, st)
		for _, a := range e.args {
			out = merge(out, r.eval(a, st))
		}
		return out
	case exprIn:
		r.eval(e.x, st)
		for _, a := range e.args {
			r.eval(a, st)
		}
	}
	return nil
}

// rootSource finds the source for a chain such as request.form.get: the root variable's
// own table is more specific than the generic prefix of the module it was imported from
// (flask.request.form is a string, flask.request.json an object).
func (r *irRun) rootSource(e *expr) (string, bool) {
	// Collect the chain a.b.c from the base variable outward.
	var chain []string
	x := e
	for x != nil && x.kind == exprMember {
		chain = append(chain, x.name)
		x = x.x
	}
	if x == nil || x.kind != exprName || r.shadow[x.name] || len(chain) == 0 {
		return "", false
	}
	slices.Reverse(chain)
	base := x.name
	// self.request.GET in a class-based view is the same request object.
	if r.spec.self[base] && chain[0] == "request" && len(chain) > 1 {
		base, chain = "request", chain[1:]
	}
	if d, ok := r.spec.sourceRoots[base][chain[0]]; ok {
		return d, true
	}
	// this.route.snapshot...: a field of the class that holds the request-like object.
	if r.spec.self[x.name] && len(chain) > 1 {
		d, ok := r.spec.sourceRoots[chain[0]][chain[1]]
		return d, ok
	}
	return "", false
}

func (r *irRun) evalMember(e *expr, st istate) (out taintSet) {
	if name, field, ok := r.pathOf(e); ok {
		defer func() { out = out.clear(st.validated(name, field)) }()
	}
	if re, ok := r.spec.sourceVarMembers[e.name]; ok && e.x != nil && e.x.kind == exprName && re.MatchString(e.x.name) && !r.shadow[e.x.name] {
		return r.source(e.pos, "web form field")
	}
	if desc, ok := r.spec.sourceMembers[e.name]; ok && !r.shadow[rootName(e)] {
		return r.source(e.pos, desc)
	}
	if desc, ok := r.rootSource(e); ok {
		return r.source(e.pos, desc)
	}
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
	r.checkExtras(e, qname, field, fn, st)
	if r.spec.weakRNG[qname] {
		// Not just a hint by name: the value itself is tracked to where it is used.
		return merge(recvT, r.source(e.pos, randomDesc))
	}
	if fn.kind == exprIndex && len(fn.args) > 0 && r.spec.name != "php" {
		// handlers[req.query.action](): the request picks which function runs.
		for _, at := range r.eval(fn.args[0], st) {
			if hit := at.kinds & kCode; hit != 0 {
				r.reachSink(e.pos, "dynamic call", hit, at, nil)
			}
		}
	}
	if fn.kind == exprMember && r.spec.mutators[fn.name] {
		var added taintSet
		for _, t := range args {
			added = merge(added, t)
		}
		if name, f, ok := r.pathOf(fn.x); ok {
			r.writeEffect(name, f, added, st)
		}
	}
	// A call on request data returns request data, unless the call is itself a sanitizer
	// (req.query.u.replace(...) strips what it strips).
	if desc, ok := r.callSource(fn); ok {
		return r.sanitized(r.source(e.pos, desc), qname, field, recvExpr)
	}
	if fn.kind == exprMember {
		if desc, ok := r.rootSource(fn); ok {
			return r.sanitized(r.source(e.pos, desc), qname, field, recvExpr)
		}
	}
	if qname != "" {
		if desc, ok := r.sourceByPrefix(qname); ok {
			return r.sanitized(r.source(e.pos, desc), qname, field, recvExpr)
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
		for _, key := range keys {
			if key != r.ctx.name {
				continue
			}
			// merge(target[key], source[key]) inside merge: a recursive deep merge that
			// descends into whatever key the input names, __proto__ included.
			for _, a := range e.args {
				if a.kind == exprIndex && len(a.args) > 0 {
					for _, at := range r.eval(a.args[0], st) {
						if hit := at.kinds & kProto; hit != 0 {
							r.reachSink(e.pos, "recursive merge", hit, at, nil)
						}
					}
				}
			}
		}
		var out taintSet
		for _, key := range keys {
			r.dependsOn(key)
			if sum, ok := r.sums[key]; ok {
				out = merge(out, r.applyIR(e, key, sum, args, recvT, st, recvExpr))
			}
		}
		return out
	}
	return all.scalar()
}

// lookupSink finds the sink for a call: by qualified name, else by method name on any
// receiver the sink admits.
func (r *irRun) lookupSink(qname string, recv *expr, field string) (sink, string, bool) {
	if s, ok := r.spec.sinks[qname]; ok && !strings.HasPrefix(qname, "?.") {
		return s, qname, true
	}
	// A Ruby call with no receiver is a call on self (select(...) inside a scope).
	implicitSelf := recv == nil && r.spec.name == "rb" && field != ""
	if (recv == nil && !implicitSelf) || field == "" {
		return sink{}, "", false
	}
	s, ok := r.spec.sinks["?."+field]
	if !ok || (implicitSelf && (len(s.recv) > 0 || s.recvUpper)) {
		return sink{}, "", false
	}
	if len(s.recv) > 0 || s.recvUpper {
		root := rootName(recv)
		upper := s.recvUpper && root != "" && root[0] >= 'A' && root[0] <= 'Z'
		// The receiver may be named by its root variable or, for a qualified static
		// reference such as DatabaseHelper.JDBCtemplate, by its last segment.
		if !upper && !containsFold(s.recv, root) && !containsFold(s.recv, lastName(recv)) {
			return sink{}, "", false
		}
	}
	return s, "." + field, true
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// lastName is the final identifier of a chain: DatabaseHelper.JDBCtemplate -> JDBCtemplate.
func lastName(e *expr) string {
	if e != nil && (e.kind == exprMember || e.kind == exprName) {
		return e.name
	}
	return ""
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

// narrow keeps the most plausible targets when several files define a method of the same
// name. Class names repeat across a codebase (Util, Helper, an inner Test), and a call must
// not pick up the summary of an unrelated class: a candidate in the current file wins,
// then one whose directory the current file imports from, and a name that is still
// ambiguous after that is not guessed at.
func (r *irRun) narrow(keys []string) []string {
	// The same method is reachable through its class and each of its supertypes.
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if len(keys) <= 1 {
		return keys
	}
	file := func(k string) string { f, _, _ := strings.Cut(k, "#"); return f }
	var same []string
	for _, k := range keys {
		if file(k) == r.mod.path {
			same = append(same, k)
		}
	}
	if len(same) > 0 {
		return same
	}
	// Different files: keep those in the same directory (the same package), else those
	// reachable through an import of the project's own code.
	dir := path.Dir(r.mod.path)
	var near []string
	for _, k := range keys {
		if path.Dir(file(k)) == dir {
			near = append(near, k)
		}
	}
	if len(near) > 0 {
		return near
	}
	files := map[string]bool{}
	for _, k := range keys {
		files[file(k)] = true
	}
	if len(files) > maxNameCandidates {
		return nil
	}
	return keys
}

// sanitized clears the kinds the callee neutralizes from t.
func (r *irRun) sanitized(t taintSet, qname, field string, recvExpr *expr) taintSet {
	if k, ok := r.spec.sanitizers[qname]; ok {
		return t.clear(k)
	}
	if k, ok := r.spec.sanitizers["?."+field]; ok && field != "" && recvExpr != nil {
		return t.clear(k)
	}
	return t
}

// targets are the summary keys of the project functions a call may reach.
func (r *irRun) targets(fn, call *expr, st istate) []string {
	var keys []string
	add := func(m *module, class, name string) {
		key := funcKey(m, &funcIR{name: name, class: class})
		if r.proj.functions[key] != nil {
			keys = append(keys, key)
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
		if r.spec.name == "rb" && fn.name == "new" && fn.x.kind == exprName && r.proj.classes[fn.x.name] != "" {
			return r.narrow(r.proj.methods[fn.x.name+".<init>"])
		}
		if r.selfName(fn.x) && r.class != "" {
			add(r.mod, r.class, fn.name)
			if len(keys) == 0 {
				keys = append(keys, r.proj.methods[r.class+"."+fn.name]...)
			}
			return r.narrow(keys)
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
						return r.narrow(keys)
					}
				}
			}
		}
		// Util.run(x): a static call on one of the project's own classes.
		if fn.x.kind == exprName && r.proj.classes[fn.x.name] != "" && !st.has(fn.x.name) {
			if ks := r.proj.methods[fn.x.name+"."+fn.name]; len(ks) > 0 {
				return r.narrow(ks)
			}
		}
		t := r.typeOf(fn.x, st)
		if t != "" {
			keys = append(keys, r.proj.methods[t+"."+fn.name]...)
			if len(keys) == 0 {
				// The type may be written out in full (org.example.Dao) while classes are
				// indexed by their simple name.
				simple := t[strings.LastIndex(t, ".")+1:]
				keys = append(keys, r.proj.methods[simple+"."+fn.name]...)
			}
		}
		if len(keys) == 0 {
			cands := r.proj.byName[fn.name]
			// A guess by method name is only reasonable for a distinctive name on a value
			// of unknown class. toString, get or close exist on every library type, and a
			// qualified library reference (Float.toString) is not a project class at all.
			if commonMethods[fn.name] || r.qualified(fn.x, st) != "" {
				return keys
			}
			if len(cands) == 0 || len(cands) > maxNameCandidates || (t != "" && r.proj.classes[t[strings.LastIndex(t, ".")+1:]] != "") {
				return r.narrow(keys)
			}
			// The receiver's class is unknown. A method name that only a few classes
			// define is a good enough guess; a common name like get or find would not be.
			keys = append(keys, cands...)
		}
	}
	return r.narrow(keys)
}

func (r *irRun) applyIR(c *expr, key string, sum *summary, args []taintSet, recvT taintSet, st istate, recvExpr *expr) taintSet {
	np := 0
	f := r.funcByKey(key)
	if f != nil {
		np = len(f.params)
	}
	argAt := func(p int, field string) taintSet {
		if p == recvParam {
			return recvT.selectField(field)
		}
		var out taintSet
		for j, t := range args {
			position := j
			if j < len(c.kw) && c.kw[j] != "" && f != nil {
				position = -1
				for i, param := range f.params {
					if param.name == c.kw[j] {
						position = i
						break
					}
				}
			}
			if position == p || (np > 0 && position >= np && p == np-1) {
				out = merge(out, t)
			}
		}
		return out.selectField(field)
	}
	callStep := "passed to " + shortName(key[strings.LastIndex(key, "#")+1:])
	for _, sk := range sum.sinks {
		for _, at := range argAt(sk.param, sk.field) {
			if hit := at.kinds & sk.kind; hit != 0 {
				at.flow = &flow{pos: c.pos, msg: callStep, prev: at.flow}
				r.reachSink(sk.pos, sk.name, hit, at, sk.flow)
			}
		}
	}
	var constructed taintSet
	for _, e := range sum.effects {
		t := substitute(e.taint, argAt).step(c.pos, "written by "+callStep[len("passed to "):])
		if e.param == recvParam && f != nil && f.name == "<init>" {
			constructed = merge(constructed, t.atField(e.field))
			continue
		}
		target := recvExpr
		if e.param != recvParam {
			if e.param >= len(c.args) {
				continue
			}
			target = c.args[e.param]
		}
		if target != nil {
			if name, field, ok := r.pathOf(target); ok {
				r.writeEffect(name, fieldJoin(field, e.field), t, st)
			}
		}
	}
	return merge(constructed, substitute(sum.ret, argAt).step(c.pos, "returned by "+callStep[len("passed to "):]))
}

func (r *irRun) funcByKey(key string) *funcIR {
	return r.proj.functions[key]
}

func (r *irRun) checkSink(c *expr, name string, s sink, args []taintSet, recv taintSet) {
	for i, want := range s.when {
		if i >= len(c.args) {
			return
		}
		if have, ok := constText(c.args[i]); !ok || !matchesAny(have, want) {
			return
		}
	}
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
	kwIdx := map[int]bool{}
	for i, k := range c.kw {
		if k != "" && slices.Contains(s.kw, k) {
			idx = append(idx, i)
			kwIdx[i] = true
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
		if i >= len(args) || (i < len(c.kw) && c.kw[i] != "" && s.kwTrue == "" && !kwIdx[i]) {
			continue
		}
		if s.strArg && c.args[i].kind == exprOther {
			continue
		}
		if s.direct && c.args[i].kind != exprName && c.args[i].kind != exprMember && c.args[i].kind != exprIndex {
			continue
		}
		isDirect := c.args[i].kind == exprName || c.args[i].kind == exprMember || c.args[i].kind == exprIndex
		for _, at := range args[i] {
			hit := at.kinds & s.kind
			if !isDirect {
				hit &^= s.directFor
			}
			if hit != 0 {
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
		if f != "" {
			r.recordEffects(name, f, t, st)
		}
	case exprIndex:
		if name, f, ok := r.pathOf(lhs); ok {
			st.write(name, f, t, false)
			r.recordEffects(name, f, t, st)
		} else if name, f, ok := r.pathOf(lhs.x); ok {
			st.write(name, f, t, true)
			r.recordEffects(name, f, t, st)
		}
	default:
		r.eval(lhs, st)
	}
}

func (r *irRun) block(list []*stmt, st istate) {
	for _, s := range list {
		r.stmt(s, st)
		if terminatesIR([]*stmt{s}) {
			break
		}
	}
}

func terminatesIR(list []*stmt) bool {
	for _, s := range list {
		switch s.kind {
		case stmtReturn, stmtJump:
			return true
		case stmtIf:
			if terminatesIR(s.then) && terminatesIR(s.els) {
				return true
			}
		}
	}
	return false
}

type validatedIR struct {
	value *expr
	kinds kind
}

func (r *irRun) validWhenTrue(c *expr, st istate) []validatedIR {
	if c == nil {
		return nil
	}
	switch c.kind {
	case exprAnd:
		return append(r.validWhenTrue(c.args[0], st), r.validWhenTrue(c.args[1], st)...)
	case exprIn:
		k := c.guard
		if k == 0 {
			k = kAll
		}
		if c.str == "prefix" {
			if !r.pathBoundary(c.x) || !r.normalizedPath(c.args[0]) {
				return nil
			}
			k = kPath
		} else if len(r.eval(c.x, st)) > 0 {
			return nil // a request-controlled collection is not a trusted allowlist
		}
		return []validatedIR{{c.args[0], k}}
	}
	return nil
}

func (r *irRun) validWhenFalse(c *expr, st istate) []validatedIR {
	if c == nil {
		return nil
	}
	switch c.kind {
	case exprNot:
		return r.validWhenTrue(c.x, st)
	case exprOr:
		return append(r.validWhenFalse(c.args[0], st), r.validWhenFalse(c.args[1], st)...)
	}
	return nil
}

func (r *irRun) markValid(vals []validatedIR, st istate) {
	for _, v := range vals {
		if name, f, ok := r.pathOf(v.value); ok {
			if !widenedField(f) {
				st.mark(name, f, v.kinds)
			}
		} else if root := rootName(v.value); root != "" && !r.spec.self[root] {
			// A check on dest.getCanonicalPath() or p.resolve(x) vouches for the variable
			// it was derived from.
			st.mark(root, "", v.kinds)
		}
	}
}

func (r *irRun) stmt(s *stmt, st istate) {
	switch s.kind {
	case stmtExpr:
		r.eval(s.rhs, st)
	case stmtAssign:
		r.lhsName = ""
		if len(s.lhs) == 1 {
			switch l := s.lhs[0]; l.kind {
			case exprName, exprMember:
				r.lhsName = l.name
			}
		}
		t := r.eval(s.rhs, st)
		r.lhsName = ""
		for _, l := range s.lhs {
			v := t
			if s.aug {
				v = merge(r.eval(l, st), t)
			}
			r.checkPollution(l, st)
			if l.kind == exprName && l.local {
				r.localNames[l.name] = true
			}
			if l.kind == exprName && !s.aug && s.rhs != nil {
				other := ""
				if s.rhs.kind == exprName && !r.strVars[s.rhs.name] && !isNumericType(r.types[s.rhs.name]) {
					other = s.rhs.name
				}
				if name, field, ok := r.pathOf(l); ok && field == "" {
					st.bind(name, other)
				}
			}
			r.assign(l, v, st)
			if l.kind == exprName {
				r.cleanPaths[l.name] = r.normalizedPath(s.rhs)
				r.boundaries[l.name] = r.pathBoundary(s.rhs)
				r.strVars[l.name] = r.isString(s.rhs) || (s.aug && r.strVars[l.name])
			}
			if l.kind == exprName {
				if sv, ok := r.strOf(s.rhs); ok && !s.aug && len(s.lhs) == 1 {
					r.strs[l.name] = sv
				} else {
					delete(r.strs, l.name)
				}
				if cv, ok := r.constInt(s.rhs); ok && !s.aug && len(s.lhs) == 1 {
					r.consts[l.name] = cv
				} else {
					delete(r.consts, l.name)
				}
			}
			r.checkAssignMisuse(l, s.rhs)
			if l.kind == exprName && !s.binds {
				if _, field, ok := r.pathOf(l); ok && field == "" {
					r.shadow[l.name] = true
				}
			}
			if l.kind != exprName {
				// session["k"] = v and flask.session[k] = v: both the key and the value are
				// written into a store the application trusts.
				container := lastName(l.x)
				if l.kind == exprMember {
					container = lastName(l.x)
				}
				k, ok := r.spec.assignRoots[container]
				if !ok {
					container = rootName(l)
					k, ok = r.spec.assignRoots[container]
				}
				if ok && !r.shadow[container] {
					written := t
					if l.kind == exprIndex && len(l.args) > 0 {
						written = merge(written, r.eval(l.args[0], st))
					}
					for _, at := range written {
						if hit := at.kinds & k; hit != 0 {
							r.reachSink(l.pos, container+"[...] = value", hit, at, nil)
						}
					}
				}
			}
			if l.kind == exprName {
				if k, ok := r.spec.nameSinks[l.name]; ok {
					for _, at := range t {
						if hit := at.kinds & k; hit != 0 {
							r.reachSink(l.pos, "$"+l.name, hit, at, nil)
						}
					}
				}
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
			if l.kind == exprName && s.rhs == nil && l.ty != "" {
				r.types[l.name] = r.resolveType(l.ty)
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
		if r.fn != nil && r.fn.htmlRoute && s.rhs != nil && r.isString(s.rhs) {
			for _, at := range t {
				if hit := at.kinds & kXSS; hit != 0 {
					r.reachSink(s.pos, "route response", hit, at, nil)
				}
			}
		}
		if r.ctx.litDeep == 0 {
			r.ctx.ret = merge(r.ctx.ret, t)
		}
	case stmtJump:
		r.eval(s.rhs, st)
		if s.next && r.continueAcc != nil {
			r.continueAcc.union(st)
		} else if s.loop && r.loopAcc != nil {
			r.loopAcc.union(st)
		}
	case stmtIf:
		r.eval(s.cond, st)
		if envConditional(s.cond) {
			r.devDepth++
			defer func() { r.devDepth-- }()
		}
		if v, ok := r.constBool(s.cond); ok {
			// The condition cannot go the other way, so only one branch runs.
			if v {
				r.block(s.then, st)
			} else {
				r.block(s.els, st)
			}
			break
		}
		forget := map[string]bool{}
		assignedNames(s.then, forget)
		assignedNames(s.els, forget)
		defer func() {
			for n := range forget {
				delete(r.consts, n)
				delete(r.strs, n)
			}
		}()
		then := st.clone()
		entryConsts, entryStrs, entryTypes, entryShadow := cloneMap(r.consts), cloneMap(r.strs), cloneMap(r.types), cloneMap(r.shadow)
		entryClean, entryBounds, entryStrings := cloneMap(r.cleanPaths), cloneMap(r.boundaries), cloneMap(r.strVars)
		entryLocals := cloneMap(r.localNames)
		if s.cond != nil {
			r.markValid(r.validWhenTrue(s.cond, st), then)
		}
		r.block(s.then, then)
		thenTypes, thenShadow := r.types, r.shadow
		thenClean, thenBounds, thenStrings := r.cleanPaths, r.boundaries, r.strVars
		r.consts, r.strs, r.types, r.shadow = cloneMap(entryConsts), cloneMap(entryStrs), cloneMap(entryTypes), cloneMap(entryShadow)
		r.cleanPaths, r.boundaries, r.strVars = cloneMap(entryClean), cloneMap(entryBounds), cloneMap(entryStrings)
		r.localNames = cloneMap(entryLocals)
		els := st.clone()
		if s.cond != nil {
			r.markValid(r.validWhenFalse(s.cond, st), els)
		}
		r.block(s.els, els)
		elseTypes, elseShadow := r.types, r.shadow
		r.localNames = entryLocals
		r.consts, r.strs = entryConsts, entryStrs
		r.types = commonMap(thenTypes, elseTypes)
		r.shadow = commonMap(thenShadow, elseShadow)
		r.cleanPaths = commonMap(thenClean, r.cleanPaths)
		r.boundaries = commonMap(thenBounds, r.boundaries)
		for name, v := range thenStrings {
			r.strVars[name] = r.strVars[name] || v
		}
		switch thenEnds, elseEnds := terminatesIR(s.then), terminatesIR(s.els); {
		case thenEnds && !elseEnds:
			st.replace(els, els)
		case elseEnds && !thenEnds:
			st.replace(then, then)
		default:
			st.replace(then, els)
		}
	case stmtLoop:
		t := r.eval(s.rhs, st).scalar()
		entryLocals := cloneMap(r.localNames)
		forget := map[string]bool{}
		assignedNames(s.then, forget)
		for n := range forget {
			delete(r.consts, n)
			delete(r.strs, n)
			delete(r.cleanPaths, n)
			delete(r.boundaries, n)
		}
		prev := r.loopAcc
		prevContinue := r.continueAcc
		r.loopAcc = istate{}
		converged := false
		for range maxLoopRounds {
			r.localNames = cloneMap(entryLocals)
			for n := range forget {
				delete(r.consts, n)
				delete(r.strs, n)
				delete(r.cleanPaths, n)
				delete(r.boundaries, n)
			}
			r.continueAcc = istate{}
			before := st.signature()
			r.eval(s.cond, st)
			body := st.clone()
			for _, l := range s.lhs {
				r.assign(l, t, body)
			}
			r.block(s.then, body)
			back := r.continueAcc
			if !terminatesIR(s.then) {
				back.union(body)
			}
			if len(back) > 0 {
				st.replace(st.clone(), back)
			}
			if before == st.signature() {
				converged = true
				break
			}
		}
		if !converged {
			r.reportLimit(s.pos, "loop analysis exceeded its convergence budget")
		}
		for n := range forget {
			delete(r.consts, n)
			delete(r.strs, n)
			delete(r.cleanPaths, n)
			delete(r.boundaries, n)
		}
		// A break leaves with the state it had, which the end of the body never sees.
		st.union(r.loopAcc)
		r.loopAcc = prev
		r.continueAcc = prevContinue
		r.localNames = entryLocals
	case stmtBranch:
		entry := st.clone()
		forget := map[string]bool{}
		for _, arm := range s.arms {
			assignedNames(arm, forget)
		}
		for n := range forget {
			delete(r.consts, n)
			delete(r.strs, n)
		}
		prev := r.loopAcc
		r.loopAcc = istate{}
		for _, arm := range s.arms {
			b := entry.clone()
			r.block(arm, b)
			st.union(b)
		}
		st.union(r.loopAcc)
		r.loopAcc = prev
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
	r.fn = f
	r.strVars = map[string]bool{}
	r.types = map[string]string{}
	r.shadow = map[string]bool{}
	r.localNames = map[string]bool{}
	r.cleanPaths = map[string]bool{}
	r.boundaries = map[string]bool{}
	r.checked = map[string]bool{}
	r.consts = map[string]int64{}
	r.strs = map[string]string{}
	if f.name != "<module>" {
		for k, v := range r.moduleStrs() {
			r.strs[k] = v
		}
		for _, p := range f.params {
			delete(r.strs, p.name)
		}
	}
	r.xxeFactories, r.xxeHardened, r.lhsName = nil, false, ""
	r.cookies, r.cookieSecure, r.cookieHTTPOnly = nil, false, false
	st := istate{}
	if f.class != "" {
		st[ikey{recvName, ""}] = taintSet{{key: "pr", param: recvParam, kinds: kAll}}
		st[ikey{recvName, originField}] = origin(recvParam)
	}
	for i, p := range f.params {
		r.localNames[p.name] = true
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
		st[ikey{p.name, originField}] = origin(i)
	}
	r.block(f.body, st)
	if len(r.cookies) > 0 && !(r.cookieSecure && r.cookieHTTPOnly) {
		for _, pos := range r.cookies {
			r.reportMisuse(pos, ruleFor2(r.spec.name, ruleCookie), "the cookie is created without Secure and HttpOnly being set to true")
		}
	}
	if !r.xxeHardened {
		for _, pos := range r.xxeFactories {
			r.reportMisuse(pos, ruleFor2(r.spec.name, ruleXXE), "the XML parser factory is used without disabling DTDs or external entities")
		}
	}
	sum := &summary{ret: r.ctx.ret, effects: r.ctx.fieldEffects()}
	seen := map[string]bool{}
	for _, k := range r.ctx.sinks {
		id := fmt.Sprintf("%d|%s|%d|%s|%d", k.param, k.field, k.kind, k.name, k.pos)
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
		if x.field != y.field {
			return x.field < y.field
		}
		if x.kind != y.kind {
			return x.kind < y.kind
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

// isString reports whether an expression is text the function built itself: a literal, a
// concatenation, or a variable holding one. A flask handler returning that text sends it
// as an HTML page; returning a Response object or a call's result does not.
func (r *irRun) isString(e *expr) bool {
	if e == nil {
		return false
	}
	switch e.kind {
	case exprStr, exprConcat:
		return true
	case exprName:
		return r.strVars[e.name]
	case exprCond, exprOr, exprAnd:
		for _, a := range e.args {
			if r.isString(a) {
				return true
			}
		}
	}
	return false
}

// strOf evaluates a string expression made of literals, known string variables, and
// Properties.getProperty calls whose key the project's .properties files define.
func (r *irRun) strOf(e *expr) (string, bool) {
	if e == nil {
		return "", false
	}
	switch e.kind {
	case exprStr:
		return e.str, true
	case exprName:
		v, ok := r.strs[e.name]
		return v, ok
	case exprConcat:
		var b strings.Builder
		for _, a := range e.args {
			v, ok := r.strOf(a)
			if !ok {
				return "", false
			}
			b.WriteString(v)
		}
		return b.String(), true
	case exprMember:
		// self::KEY, static::KEY: a constant of the class being analyzed, kept by name.
		if e.x != nil && e.x.kind == exprName && (e.x.name == "self" || e.x.name == "static") && r.mod != nil {
			v, ok := topStrs(r.mod)[e.name]
			return v, ok
		}
		// Constants.KEY where Constants is one of the project's classes.
		if e.x != nil && e.x.kind == exprName && r.proj != nil {
			if path := r.proj.classes[e.x.name]; path != "" {
				if m := r.proj.mods[path]; m != nil {
					v, ok := topStrs(m)[e.name]
					return v, ok
				}
			}
		}
		// cfg.SECRET where cfg is a project module.
		if e.x != nil && e.x.kind == exprName && r.mod != nil {
			if ref, ok := r.mod.locals[e.x.name]; ok && ref.name == "" {
				if m := r.proj.resolveModule(r.mod, ref.spec); m != nil && m != r.mod {
					v, ok := topStrs(m)[e.name]
					return v, ok
				}
			}
		}
	case exprCall:
		if e.x != nil && e.x.kind == exprMember && e.x.name == "getProperty" && len(e.args) > 0 && e.args[0].kind == exprStr {
			if v, ok := r.proj.props[e.args[0].str]; ok {
				return v, true
			}
			if len(e.args) > 1 {
				return r.strOf(e.args[1])
			}
		}
	}
	return "", false
}

// argText is the lower-cased text of an argument for matching: a string the analysis can
// work out, else the literal or name as written.
func (r *irRun) argText(e *expr) (string, bool) {
	if v, ok := r.strOf(e); ok {
		return strings.ToLower(v), true
	}
	return constText(e)
}

// moduleStrs are the string constants a function can read without assigning them: its
// module's own (const SECRET = "...") and the ones it imports from another project file.
func (r *irRun) moduleStrs() map[string]string {
	out := map[string]string{}
	for k, v := range topStrs(r.mod) {
		out[k] = v
	}
	for alias, ref := range r.mod.locals {
		if ref.name == "" {
			continue
		}
		if m := r.proj.resolveModule(r.mod, ref.spec); m != nil && m != r.mod {
			if v, ok := topStrs(m)[ref.name]; ok {
				out[alias] = v
			}
		}
	}
	return out
}

// topStrs are a module's top-level names that are assigned a string exactly once. A name
// that is assigned again at the top level is left out.
func topStrs(m *module) map[string]string {
	if m.topStrs != nil {
		return m.topStrs
	}
	out := map[string]string{}
	m.topStrs = out
	count := map[string]int{}
	for _, s := range m.top {
		if s.kind != stmtAssign {
			continue
		}
		for _, l := range s.lhs {
			if l.kind == exprName {
				count[l.name]++
			}
		}
	}
	var eval func(e *expr) (string, bool)
	eval = func(e *expr) (string, bool) {
		switch {
		case e == nil:
			return "", false
		case e.kind == exprStr:
			return e.str, true
		case e.kind == exprName:
			v, ok := out[e.name]
			return v, ok
		case e.kind == exprConcat:
			var b strings.Builder
			for _, a := range e.args {
				v, ok := eval(a)
				if !ok {
					return "", false
				}
				b.WriteString(v)
			}
			return b.String(), true
		}
		return "", false
	}
	for _, s := range m.top {
		if s.kind != stmtAssign || s.aug || len(s.lhs) != 1 || s.lhs[0].kind != exprName || count[s.lhs[0].name] != 1 {
			continue
		}
		if v, ok := eval(s.rhs); ok {
			out[s.lhs[0].name] = v
		}
	}
	return out
}
