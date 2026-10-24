package sast

import "strings"

const pythonPathField = "\x00python-path"

func (p *project) pythonConstantAssignments(a *pythonRouteAnalysis) {
	p.pyConstantWrites = map[string]bool{}
	var collect func(*module, *funcIR, []*stmt)
	collect = func(m *module, f *funcIR, body []*stmt) {
		for _, s := range body {
			for _, lhs := range s.lhs {
				base := lhs
				if base.kind == exprIndex {
					base = base.x
				}
				if q := a.qualified(m, f, base); strings.HasPrefix(q, "flask.request.") {
					a.requestWrites[f] = true
				}
				if lhs.kind == exprName && f != nil {
					p.pyConstantWrites[m.path+"#"+lhs.name] = true
				}
				if lhs.kind == exprMember {
					q := a.qualified(m, f, lhs)
					if i := strings.LastIndexByte(q, '.'); i > 0 {
						if target := p.resolveModule(m, q[:i]); target != nil {
							p.pyConstantWrites[target.path+"#"+q[i+1:]] = true
						}
					}
				}
			}
			collect(m, f, s.then)
			collect(m, f, s.els)
			for _, arm := range s.arms {
				collect(m, f, arm)
			}
		}
	}
	for m := range a.globals {
		collect(m, nil, m.top)
		for _, f := range m.funcs {
			collect(m, f, f.body)
		}
	}
}

func pythonExactMetadata(field string) bool {
	return field == parsedURLField || field == pythonPathField
}

// Path shape is a branch-local fact, not a sanitizer. In particular an absolute
// base without a directory boundary still allows sibling-prefix traversal.
func (r *irRun) pythonPathValue(e *expr, st istate) string {
	if r.spec.name != "py" || e == nil {
		return ""
	}
	if e.kind == exprName {
		if value := st[ikey{e.name, pythonPathField}]; len(value) == 1 {
			return value[0].key
		}
	}
	if e.kind == exprOther && e.str == "/" && len(e.args) == 2 {
		if strings.HasPrefix(r.pythonPathValue(e.args[0], st), "path:") || strings.HasPrefix(r.pythonPathValue(e.args[1], st), "path:") {
			return "path:unknown"
		}
	}
	if e.kind != exprCall {
		return ""
	}
	q, _, _ := r.resolve(e.x, st)
	root := rootName(e.x)
	if q == "str" && !r.shadow[root] && !r.localNames[root] && len(e.args) == 1 && positionalOnly(e) {
		if value := r.pythonPathValue(e.args[0], st); strings.HasPrefix(value, "path:") {
			return "text:" + strings.TrimPrefix(value, "path:")
		}
	}
	if isPythonPath(q) && !r.shadow[root] && !r.localNames[root] && r.proj.resolveModule(r.mod, "pathlib") == nil {
		if len(e.args) == 1 && positionalOnly(e) {
			if text, known := r.pythonPathConstant(e.args[0], st); known {
				for strings.HasPrefix(text, "./") {
					text = strings.TrimPrefix(text, "./")
				}
				// Exclude one-letter and drive-relative prefixes: on Windows an
				// absolute C:\\... can start with the relative Path("C").
				if len(text) >= 2 && text != ".." && !strings.ContainsAny(text, "/\\:") {
					return "path:relative-prefix"
				}
			}
		}
		return "path:unknown"
	}
	if e.x.kind == exprMember && strings.HasPrefix(r.pythonPathValue(e.x.x, st), "path:") {
		switch e.x.name {
		case "resolve", "absolute":
			return "path:absolute"
		case "joinpath", "with_name", "with_suffix", "expanduser":
			return "path:unknown"
		}
	}
	return ""
}

func (r *irRun) pythonPathConstant(e *expr, st istate) (string, bool) {
	if e == nil {
		return "", false
	}
	if e.kind == exprMember {
		root := rootName(e)
		if !r.shadow[root] && !r.localNames[root] {
			q := r.qualified(e, st)
			if i := strings.LastIndexByte(q, '.'); i > 0 {
				if m := r.proj.resolveModule(r.mod, q[:i]); m != nil && !r.proj.pyConstantWrites[m.path+"#"+q[i+1:]] {
					text, known := topStrs(m)[q[i+1:]]
					return text, known
				}
			}
		}
		return "", false
	}
	if e.kind == exprName {
		if ref, imported := r.mod.locals[e.name]; imported && ref.name != "" {
			if m := r.proj.resolveModule(r.mod, ref.spec); m != nil && r.proj.pyConstantWrites[m.path+"#"+ref.name] {
				return "", false
			}
		}
	}
	return r.strOf(e)
}

func (r *irRun) conditionBool(e *expr, st istate) (bool, bool) {
	if value, known := r.constBool(e); known {
		return value, true
	}
	if r.spec.name == "py" && e != nil {
		if e.kind == exprNot {
			value, known := r.conditionBool(e.x, st)
			return !value, known
		}
		if e.kind == exprIn && e.str == "prefix" && len(e.args) == 1 && r.pythonPathValue(e.args[0], st) == "text:absolute" && r.pythonPathValue(e.x, st) == "text:relative-prefix" {
			return false, true
		}
	}
	return false, false
}
