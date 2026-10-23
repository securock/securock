package sast

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// A guard is a check that rejects unexpected input before it is used:
//
//	if !allowed[col] { return }
//	if !ident.MatchString(col) { return }
//
// Past such a check the value is one of a known set (a map key, a slice member, or text
// matched by a strict anchored pattern), so it can no longer carry an injection payload.
// Only guards whose failure leaves the function are trusted; a check that merely logs
// proves nothing.

// validWhenTrue returns the values that are known good if cond is true.
func (a *analyzer) validWhenTrue(cond ast.Expr) []ast.Expr {
	switch c := unparen(cond).(type) {
	case *ast.BinaryExpr:
		if c.Op == token.LAND {
			return append(a.validWhenTrue(c.X), a.validWhenTrue(c.Y)...)
		}
	case *ast.IndexExpr:
		// m[x] on a map[string]bool is true only for keys that were put in it.
		if m, ok := typeUnder(a.info.TypeOf(c.X)).(*types.Map); ok && isBool(m.Elem()) {
			return []ast.Expr{c.Index}
		}
	case *ast.Ident:
		if x, ok := a.ctx.oks[a.info.Uses[c]]; ok {
			return []ast.Expr{x}
		}
	case *ast.CallExpr:
		return a.validatorCall(c)
	}
	return nil
}

// validWhenFalse returns the values that are known good if cond is false.
func (a *analyzer) validWhenFalse(cond ast.Expr) []ast.Expr {
	switch c := unparen(cond).(type) {
	case *ast.CallExpr:
		// if strings.Contains(name, "..") { reject }
		if name, _ := a.calleeName(c.Fun); name == "strings.Contains" && len(c.Args) == 2 {
			if tv := a.info.Types[c.Args[1]]; tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == ".." {
				return []ast.Expr{c.Args[0]}
			}
		}
	case *ast.UnaryExpr:
		if c.Op == token.NOT {
			return a.validWhenTrue(c.X)
		}
	case *ast.BinaryExpr:
		if c.Op == token.LOR {
			return append(a.validWhenFalse(c.X), a.validWhenFalse(c.Y)...)
		}
	}
	return nil
}

// typeUnder is t.Underlying(), or nil for an unresolved type.
func typeUnder(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}

func isBool(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsBoolean != 0
}

func (a *analyzer) validatorCall(c *ast.CallExpr) []ast.Expr {
	name, recv := a.calleeName(c.Fun)
	switch name {
	case "slices.Contains":
		if len(c.Args) == 2 {
			return []ast.Expr{c.Args[1]}
		}
	case "path/filepath.IsLocal":
		if len(c.Args) == 1 {
			return []ast.Expr{c.Args[0]}
		}
	case "strings.HasPrefix":
		// A prefix check is only a containment check once the path has been cleaned:
		// "/srv/" + name passes it for "../etc/passwd", filepath.Join("/srv", name) does not.
		if len(c.Args) == 2 {
			if obj, _, _, ok := a.pathOf(c.Args[0]); ok && a.ctx.cleaned[obj] {
				return []ast.Expr{c.Args[0]}
			}
		}
	case "(*regexp.Regexp).MatchString", "(*regexp.Regexp).Match":
		if len(c.Args) == 1 && recv != nil && a.strictPattern(recv) {
			return []ast.Expr{c.Args[0]}
		}
	}
	return nil
}

// strictPattern reports whether the regexp variable was built from a constant, anchored
// pattern that only admits harmless characters.
func (a *analyzer) strictPattern(e ast.Expr) bool {
	obj, _, _, ok := a.pathOf(e)
	if !ok {
		return false
	}
	pat, ok := a.regexps[obj]
	return ok && strictRegexp(pat)
}

// strictRegexp accepts ^...$ patterns made only of letters, digits and a few separators,
// with no wildcard, alternation, negated class, or whitespace class.
func strictRegexp(p string) bool {
	if len(p) < 3 || p[0] != '^' || p[len(p)-1] != '$' {
		return false
	}
	p = p[1 : len(p)-1]
	inClass := false
	for i := 0; i < len(p); i++ {
		ch := p[i]
		switch {
		case ch == '\\':
			i++
			if i >= len(p) || !strings.ContainsRune(`wd.-_@`, rune(p[i])) {
				return false
			}
		case inClass && ch == ']':
			inClass = false
		case inClass:
			// Inside [...] a dot is a literal dot.
			if !safeLiteral(ch) && ch != '.' {
				return false
			}
		case ch == '[':
			inClass = true
			if i+1 < len(p) && p[i+1] == '^' {
				return false
			}
		case strings.ContainsRune("+*?(){},:", rune(ch)):
			// quantifiers and groups; "|" and "." are deliberately absent
		case safeLiteral(ch) && ch != '.':
		default:
			return false
		}
	}
	return !inClass
}

func safeLiteral(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_-@+", c) >= 0
}

// markValid clears taint from the validated values.
func (a *analyzer) markValid(vals []ast.Expr, st state) {
	for _, v := range vals {
		if obj, field, _, ok := a.pathOf(v); ok {
			st.write(obj, field, nil, false)
			st.mark(obj, field)
		}
	}
}

// terminates reports whether control cannot continue past the end of the list.
func terminates(list []ast.Stmt) bool {
	if len(list) == 0 {
		return false
	}
	switch s := list[len(list)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return s.Tok != token.FALLTHROUGH
	case *ast.ExprStmt:
		if c, ok := s.X.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "panic" {
				return true
			}
		}
	case *ast.BlockStmt:
		return terminates(s.List)
	}
	return false
}

// noteOK remembers "v, ok := m[k]" so that a later check of ok validates k.
func (a *analyzer) noteOK(s *ast.AssignStmt) {
	if len(s.Lhs) != 2 || len(s.Rhs) != 1 {
		return
	}
	ix, ok := unparen(s.Rhs[0]).(*ast.IndexExpr)
	if !ok {
		return
	}
	if _, isMap := typeUnder(a.info.TypeOf(ix.X)).(*types.Map); !isMap {
		return
	}
	if id, ok := s.Lhs[1].(*ast.Ident); ok && id.Name != "_" {
		if o := a.info.ObjectOf(id); o != nil {
			a.ctx.oks[o] = ix.Index
		}
	}
}

// collectRegexps finds variables initialized with regexp.MustCompile of a constant.
func collectRegexps(files []*ast.File, info *types.Info, into map[types.Object]string) {
	pattern := func(e ast.Expr) (string, bool) {
		c, ok := e.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			return "", false
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "MustCompile" && sel.Sel.Name != "Compile") {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		if pn, ok := info.Uses[id].(*types.PkgName); !ok || pn.Imported().Path() != "regexp" {
			return "", false
		}
		tv := info.Types[c.Args[0]]
		if tv.Value == nil || tv.Value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(tv.Value), true
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ValueSpec:
				for i, v := range n.Values {
					if p, ok := pattern(v); ok && i < len(n.Names) {
						into[info.Defs[n.Names[i]]] = p
					}
				}
			case *ast.AssignStmt:
				for i, v := range n.Rhs {
					if id, ok := n.Lhs[min(i, len(n.Lhs)-1)].(*ast.Ident); ok && n.Tok == token.DEFINE {
						if p, ok := pattern(v); ok {
							into[info.Defs[id]] = p
						}
					}
				}
			}
			return true
		})
	}
}

// strictLiteral reports whether a regular expression written as a literal in source
// admits only harmless text. delim names the delimiters to strip ("/" for /re/flags and
// PHP strings, "" for a bare pattern), and the engine-specific anchors \A and \z are
// read as ^ and $. full means the match API only succeeds on the whole input
// (Java's String.matches), so the anchors are implied.
func strictLiteral(src string, delim string, full bool) bool {
	p := strings.TrimSpace(src)
	if delim != "" && strings.HasPrefix(p, delim) {
		if i := strings.LastIndex(p, delim); i > 0 {
			p = p[1:i]
		}
	}
	p = strings.NewReplacer(`\A`, "^", `\z`, "$", `\Z`, "$").Replace(p)
	if full {
		if !strings.HasPrefix(p, "^") {
			p = "^" + p
		}
		if !strings.HasSuffix(p, "$") {
			p += "$"
		}
	}
	return strictRegexp(p)
}

// guardOf builds the membership form the engine reads as a validation of value.
func guardOf(pos token.Pos, value *expr) *expr {
	return &expr{kind: exprIn, pos: pos, x: &expr{kind: exprNum, pos: pos}, args: []*expr{value}}
}
