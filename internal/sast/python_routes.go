package sast

import "strings"

type pythonRoute struct {
	receiver *expr
	path     string
	known    bool
}

func (p *pyLower) routePatterns(def *node) []pythonRoute {
	var routes []pythonRoute
	for _, decorator := range p.named(def) {
		if p.kind(decorator) != "decorator" {
			continue
		}
		route := pythonRoute{}
		cs := p.named(decorator)
		if len(cs) == 1 && p.kind(cs[0]) == "call" {
			call := p.expr(cs[0])
			if call.x.kind == exprMember && (call.x.name == "route" || call.x.name == "get" || call.x.name == "post") {
				route.receiver = call.x.x
				for i, arg := range call.args {
					if i == 0 && call.kw[i] == "" || call.kw[i] == "rule" {
						if arg.kind == exprStr && !arg.unknownText {
							route.path, route.known = arg.str, true
						}
					}
				}
			}
		}
		// Unknown wrappers and route expressions cannot establish a path constraint.
		routes = append(routes, route)
	}
	return routes
}

type pythonCall struct {
	mod     *module
	caller  *funcIR
	call    *expr
	targets []*funcIR
	unknown bool
}

type pythonRouteAnalysis struct {
	proj          *project
	owners        map[*funcIR]*module
	globals       map[*module]map[string]*expr
	bindings      map[*funcIR]map[string]*expr
	locals        map[*module]map[string][]*funcIR
	byName        map[string][]*funcIR
	params        map[*funcIR]map[string]string
	requestWrites map[*funcIR]bool
}

// Infer router ownership from constructors and registration calls, including
// project modules loaded through importlib. An unknown or conflicting caller
// leaves the registrar parameter unknown; a Blueprint is never a Flask app.
func (p *project) pythonRoutes() {
	a := &pythonRouteAnalysis{proj: p, owners: map[*funcIR]*module{}, globals: map[*module]map[string]*expr{}, bindings: map[*funcIR]map[string]*expr{}, locals: map[*module]map[string][]*funcIR{}, byName: map[string][]*funcIR{}, params: map[*funcIR]map[string]string{}, requestWrites: map[*funcIR]bool{}}
	for _, m := range p.mods {
		if m.lang != "py" {
			continue
		}
		a.globals[m] = pythonBindings(m.top)
		a.locals[m] = map[string][]*funcIR{}
		for _, f := range m.funcs {
			a.owners[f] = m
			a.bindings[f] = pythonBindings(f.body)
			a.locals[m][f.name] = append(a.locals[m][f.name], f)
			if f.class == "" && f.pyOuter == nil {
				a.byName[f.name] = append(a.byName[f.name], f)
			}
		}
	}
	p.pythonConstantAssignments(a)
	var calls []pythonCall
	escapes := map[*funcIR]bool{}
	for m := range a.globals {
		visit := func(f *funcIR, e, parent *expr) {
			if a.qualified(m, f, e) == "flask.request" && (parent == nil || parent.kind != exprMember || parent.x != e) {
				a.requestWrites[f] = true // the mutable request object escapes
			}
			if e.kind == exprCall {
				if e.x.kind == exprMember && a.qualified(m, f, e.x.x) == "flask.request" && e.x.name != "get_json" && e.x.name != "get_data" {
					a.requestWrites[f] = true
				}
				targets, unknown := a.targets(m, f, e.x, 0)
				if len(targets) > 0 {
					calls = append(calls, pythonCall{m, f, e, targets, unknown})
				}
			}
			if (e.kind == exprName || e.kind == exprMember) && (parent == nil || parent.kind != exprCall || parent.x != e) {
				targets, _ := a.targets(m, f, e, 0)
				for _, target := range targets {
					escapes[target] = true
				}
			}
		}
		pythonWalk(m.top, func(e, parent *expr) { visit(nil, e, parent) })
		for _, f := range m.funcs {
			pythonWalk(f.body, func(e, parent *expr) { visit(f, e, parent) })
		}
	}
	for changed := true; changed; {
		changed = false
		for _, call := range calls {
			for _, target := range call.targets {
				if a.requestWrites[target] && !a.requestWrites[call.caller] {
					a.requestWrites[call.caller] = true
					changed = true
				}
			}
		}
	}
	for range 8 {
		next := map[*funcIR]map[string]string{}
		for _, call := range calls {
			for _, target := range call.targets {
				if next[target] == nil {
					next[target] = map[string]string{}
				}
				for i, param := range target.params {
					ty := "?"
					if !call.unknown && !escapes[target] && positionalOnly(call.call) && len(call.call.args) == len(target.params) {
						if value := a.valueType(call.mod, call.caller, call.call.args[i], 0); value != "" {
							ty = value
						}
					}
					previous := next[target][param.name]
					if previous != "" && previous != ty {
						ty = "?"
					}
					next[target][param.name] = ty
				}
			}
		}
		a.params = next
	}
	paths := map[*funcIR]string{}
	for f, m := range a.owners {
		if len(f.pyRoutes) == 0 || escapes[f] || a.requestWrites[f] {
			continue
		}
		valid := true
		path := f.pyRoutes[0].path
		for _, route := range f.pyRoutes {
			if !route.known || route.path != path || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "<>%\\") || a.valueType(m, f, route.receiver, 0) != "flask.Flask" {
				valid = false
			}
		}
		if valid {
			paths[f] = path
		}
	}
	// A direct helper call must be in a handler with the same path constraint.
	// Plain calls and extra registrations/escaping references discard the proof.
	for changed := true; changed; {
		changed = false
		for _, call := range calls {
			for _, target := range call.targets {
				if path, ok := paths[target]; ok && (call.unknown || paths[call.caller] != path) {
					delete(paths, target)
					changed = true
				}
			}
		}
	}
	p.pyRouteParts = map[*funcIR][]string{}
	for f, path := range paths {
		parts := strings.Split(path, "/")
		if len(parts) <= maxSequenceElements {
			p.pyRouteParts[f] = parts
		}
	}
}

func pythonBindings(body []*stmt) map[string]*expr {
	bindings := map[string]*expr{}
	seen := map[string]bool{}
	var collect func([]*stmt)
	collect = func(body []*stmt) {
		for _, s := range body {
			for _, lhs := range s.lhs {
				if lhs.kind != exprName {
					continue
				}
				value := s.rhs
				if seen[lhs.name] || s.kind != stmtAssign || s.aug || len(s.lhs) != 1 {
					value = nil
				}
				bindings[lhs.name], seen[lhs.name] = value, true
			}
			collect(s.then)
			collect(s.els)
			for _, arm := range s.arms {
				collect(arm)
			}
		}
	}
	collect(body)
	return bindings
}

func (a *pythonRouteAnalysis) binding(m *module, f *funcIR, name string) (*expr, *funcIR, bool) {
	for scope := f; scope != nil; scope = scope.pyOuter {
		if value, ok := a.bindings[scope][name]; ok {
			return value, scope, true
		}
		for _, param := range scope.params {
			if param.name == name {
				return nil, scope, true
			}
		}
	}
	value, ok := a.globals[m][name]
	return value, nil, ok
}

func (a *pythonRouteAnalysis) qualified(m *module, f *funcIR, e *expr) string {
	return a.qualifiedAt(m, f, e, 0)
}

func (a *pythonRouteAnalysis) qualifiedAt(m *module, f *funcIR, e *expr, depth int) string {
	if e == nil || depth > 12 {
		return ""
	}
	if e.kind == exprName {
		if value, scope, bound := a.binding(m, f, e.name); bound {
			return a.qualifiedAt(m, scope, value, depth+1)
		}
		return m.imports[e.name]
	}
	if e.kind == exprMember {
		if root := a.qualifiedAt(m, f, e.x, depth+1); root != "" {
			return root + "." + e.name
		}
	}
	return ""
}

func (a *pythonRouteAnalysis) valueType(m *module, f *funcIR, e *expr, depth int) string {
	if e == nil || depth > 12 {
		return ""
	}
	if e.kind == exprCall {
		q := a.qualified(m, f, e.x)
		if (q == "flask.Flask" || q == "flask.Blueprint") && a.proj.resolveModule(m, "flask") == nil {
			return q
		}
	}
	if e.kind == exprName {
		if value, scope, bound := a.binding(m, f, e.name); bound {
			if scope == nil {
				if a.proj.pyConstantWrites[m.path+"#"+e.name] {
					return ""
				}
				if _, imported := m.locals[e.name]; imported {
					return ""
				}
			}
			if value != nil {
				return a.valueType(m, scope, value, depth+1)
			}
			if _, assigned := a.bindings[scope][e.name]; assigned {
				return ""
			}
			return a.params[scope][e.name]
		}
		if ref, ok := m.locals[e.name]; ok && ref.name != "" {
			if other := a.proj.resolveModule(m, ref.spec); other != nil {
				return a.valueType(other, nil, &expr{kind: exprName, name: ref.name}, depth+1)
			}
		}
	}
	if e.kind == exprMember && e.x.kind == exprName {
		if _, _, bound := a.binding(m, f, e.x.name); bound {
			return ""
		}
		if ref, ok := m.locals[e.x.name]; ok && ref.name == "" {
			if other := a.proj.resolveModule(m, ref.spec); other != nil {
				return a.valueType(other, nil, &expr{kind: exprName, name: e.name}, depth+1)
			}
		}
	}
	return ""
}

func (a *pythonRouteAnalysis) targets(m *module, f *funcIR, e *expr, depth int) ([]*funcIR, bool) {
	if e == nil || depth > 12 {
		return nil, true
	}
	if e.kind == exprName {
		if value, scope, bound := a.binding(m, f, e.name); bound {
			return a.targets(m, scope, value, depth+1)
		}
		if ref, ok := m.locals[e.name]; ok && ref.name != "" {
			if other := a.proj.resolveModule(m, ref.spec); other != nil {
				return a.locals[other][ref.name], false
			}
			return nil, true
		}
		return a.locals[m][e.name], false
	}
	if e.kind == exprMember && e.x.kind == exprName {
		if value, scope, bound := a.binding(m, f, e.x.name); bound {
			if value != nil && value.kind == exprCall && a.qualified(m, scope, value.x) == "importlib.import_module" && a.proj.resolveModule(m, "importlib") == nil {
				if len(value.args) == 1 && value.args[0].kind == exprStr && !value.args[0].unknownText {
					if other := a.proj.resolveModule(m, value.args[0].str); other != nil {
						return a.locals[other][e.name], false
					}
					return nil, true
				}
				return a.byName[e.name], false
			}
			return a.byName[e.name], true
		}
		if ref, ok := m.locals[e.x.name]; ok && ref.name == "" {
			if other := a.proj.resolveModule(m, ref.spec); other != nil {
				return a.locals[other][e.name], false
			}
		}
		return a.byName[e.name], true
	}
	return nil, true
}

func pythonWalk(body []*stmt, visit func(*expr, *expr)) {
	var walk func(*expr, *expr)
	walk = func(e, parent *expr) {
		if e == nil {
			return
		}
		visit(e, parent)
		walk(e.x, e)
		for _, arg := range e.args {
			walk(arg, e)
		}
		if e.fn != nil {
			pythonWalk(e.fn.body, visit)
		}
	}
	for _, s := range body {
		walk(s.rhs, nil)
		walk(s.cond, nil)
		for _, lhs := range s.lhs {
			walk(lhs, nil)
		}
		pythonWalk(s.then, visit)
		pythonWalk(s.els, visit)
		for _, arm := range s.arms {
			pythonWalk(arm, visit)
		}
	}
}

func (r *irRun) pythonRouteSplit(e *expr, st istate) ([]string, bool) {
	if r.spec.name != "py" || e == nil || e.kind != exprCall || e.x.kind != exprMember || e.x.name != "split" || len(e.args) != 1 || !positionalOnly(e) {
		return nil, false
	}
	parts, known := r.proj.pyRouteParts[r.fn]
	root := rootName(e.x.x)
	if !known || r.shadow[root] || r.localNames[root] || r.qualified(e.x.x, st) != "flask.request.path" {
		return nil, false
	}
	separator, literal := r.strOf(e.args[0])
	return parts, literal && separator == "/"
}
