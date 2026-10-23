package sast

import "strings"

// Kotlin shares the JVM libraries with Java (servlets, JDBC, Spring), so it uses a copy
// of the Java model; only the syntax differs. The copy is made in lang_zkotlin.go, after
// every other file has finished extending the Java tables.

type ktLower struct {
	*lowering
	class     string
	classCORS bool
}

func lowerKotlin(l *lowering) *module {
	k := &ktLower{lowering: l}
	k.members(l.named(l.root))
	return l.mod
}

func (k *ktLower) members(ns []*node) {
	for _, n := range ns {
		switch k.kind(n) {
		case "import_list":
			k.members(k.named(n))
		case "import_header":
			k.importHeader(n)
		case "class_declaration", "object_declaration", "companion_object":
			k.classDecl(n)
		case "function_declaration":
			k.function(n, "")
		}
	}
}

func (k *ktLower) importHeader(n *node) {
	id := k.firstOfKind(n, "identifier")
	if id == nil {
		return
	}
	full := strings.ReplaceAll(strings.TrimSpace(k.text(id)), "\n", "")
	if k.firstOfKind(n, "wildcard_import") != nil {
		return
	}
	alias := full[strings.LastIndex(full, ".")+1:]
	if a := k.firstOfKind(n, "import_alias"); a != nil {
		alias = strings.TrimSpace(strings.TrimPrefix(k.text(a), "as"))
	}
	k.mod.imports[alias] = full
}

func (k *ktLower) firstOfKind(n *node, kind string) *node {
	for _, c := range k.named(n) {
		if k.kind(c) == kind {
			return c
		}
	}
	return nil
}

// ident is the text of the first simple_identifier or type_identifier child.
func (k *ktLower) ident(n *node) string {
	for _, c := range k.named(n) {
		if kk := k.kind(c); kk == "simple_identifier" || kk == "type_identifier" {
			return k.text(c)
		}
	}
	return ""
}

func (k *ktLower) typeName(n *node) string {
	if n == nil {
		return ""
	}
	s := k.text(n)
	s = strings.TrimSuffix(s, "?")
	if i := strings.IndexAny(s, "<"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// typeOf finds the declared type among the children of a parameter or declaration.
func (k *ktLower) declaredType(n *node) string {
	for _, c := range k.named(n) {
		switch k.kind(c) {
		case "user_type", "nullable_type":
			return k.typeName(c)
		}
	}
	return ""
}

func (k *ktLower) annotations(mod *node) []string {
	var out []string
	if mod == nil {
		return nil
	}
	for _, a := range k.named(mod) {
		if k.kind(a) == "annotation" {
			out = append(out, k.text(a))
		}
	}
	return out
}

func annotationName(t string) string {
	t = strings.TrimPrefix(t, "@")
	if i := strings.Index(t, "("); i >= 0 {
		t = t[:i]
	}
	return strings.TrimSpace(t)
}

func (k *ktLower) classDecl(n *node) {
	name := k.ident(n)
	if name == "" {
		name = k.class
	}
	prev, prevCORS := k.class, k.classCORS
	k.class = name
	k.classCORS = false
	defer func() { k.class, k.classCORS = prev, prevCORS }()
	controller := false
	if mod := k.firstOfKind(n, "modifiers"); mod != nil {
		for _, a := range k.annotations(mod) {
			switch annotationName(a) {
			case "RestController", "Controller":
				controller = true
			}
			if strings.Contains(a, "CrossOrigin") && reCredentials.MatchString(a) && !reSpecificOrigin.MatchString(a) {
				k.classCORS = true
			}
		}
	}
	for _, c := range k.named(n) {
		switch k.kind(c) {
		case "delegation_specifiers", "delegation_specifier":
			for _, b := range k.named(c) {
				k.mod.supers[name] = append(k.mod.supers[name], k.typeName(b))
			}
		case "primary_constructor":
			init := &funcIR{name: "<init>", class: name, pos: k.pos(c)}
			var stmts []*stmt
			for _, cp := range k.named(c) {
				if k.kind(cp) != "class_parameter" {
					continue
				}
				pname := ""
				for _, x := range k.named(cp) {
					if k.kind(x) == "simple_identifier" {
						pname = k.text(x)
					}
				}
				ty := k.declaredType(cp)
				init.params = append(init.params, param{name: pname, ty: ty})
				// val/var parameters are fields.
				if k.firstOfKind(cp, "binding_pattern_kind") != nil && ty != "" {
					if k.mod.fields[name] == nil {
						k.mod.fields[name] = map[string]string{}
					}
					k.mod.fields[name][pname] = ty
					stmts = append(stmts, &stmt{kind: stmtAssign, pos: k.pos(cp), lhs: []*expr{{kind: exprMember, pos: k.pos(cp), x: &expr{kind: exprName, name: "this"}, name: pname}}, rhs: &expr{kind: exprName, pos: k.pos(cp), name: pname}})
				}
			}
			init.body = stmts
			k.mod.funcs = append(k.mod.funcs, init)
		case "class_body":
			for _, m := range k.named(c) {
				switch k.kind(m) {
				case "function_declaration":
					k.function(m, name)
				case "property_declaration":
					k.fieldDecl(name, m)
				case "class_declaration", "object_declaration", "companion_object":
					k.classDecl(m)
				}
			}
		}
	}
	_ = controller
}

func (k *ktLower) fieldDecl(class string, m *node) {
	vd := k.firstOfKind(m, "variable_declaration")
	if vd == nil {
		return
	}
	ty := k.declaredType(vd)
	if ty == "" {
		return
	}
	if k.mod.fields[class] == nil {
		k.mod.fields[class] = map[string]string{}
	}
	k.mod.fields[class][k.ident(vd)] = ty
}

func (k *ktLower) function(m *node, class string) {
	f := &funcIR{name: k.ident(m), class: class, pos: k.pos(m)}
	var mod *node
	for _, c := range k.named(m) {
		if k.kind(c) == "modifiers" {
			mod = c
		}
	}
	action := false
	cors := k.classCORS
	for _, a := range k.annotations(mod) {
		n := annotationName(a)
		if strings.HasSuffix(n, "Mapping") {
			action = true
		}
		if strings.Contains(a, "CrossOrigin") && reCredentials.MatchString(a) && !reSpecificOrigin.MatchString(a) {
			cors = true
		}
	}
	_ = action
	if ps := k.firstOfKind(m, "function_value_parameters"); ps != nil {
		pendingSource := ""
		for _, c := range k.named(ps) {
			switch k.kind(c) {
			case "parameter_modifiers":
				for _, a := range k.annotations(c) {
					if d, ok := javaSourceAnnotations[annotationName(a)]; ok {
						pendingSource = d
					}
				}
			case "parameter":
				pr := param{name: k.ident(c), ty: k.declaredType(c), source: pendingSource}
				if mm := k.firstOfKind(c, "parameter_modifiers"); mm != nil {
					for _, a := range k.annotations(mm) {
						if d, ok := javaSourceAnnotations[annotationName(a)]; ok {
							pr.source = d
						}
					}
				}
				pendingSource = ""
				if f.name == "main" && pr.ty == "Array" {
					pr.source = "command-line arguments"
				}
				f.params = append(f.params, pr)
			}
		}
	}
	if fb := k.firstOfKind(m, "function_body"); fb != nil {
		if st := k.firstOfKind(fb, "statements"); st != nil {
			f.body = k.stmts(k.named(st))
		} else {
			for _, c := range k.named(fb) {
				f.body = []*stmt{{kind: stmtReturn, pos: k.pos(c), rhs: k.expr(c)}}
			}
		}
	} else {
		return // an abstract or interface function
	}
	if cors {
		f.body = append([]*stmt{synthCall(k.lowering, m, "corsAnyOrigin")}, f.body...)
	}
	k.mod.funcs = append(k.mod.funcs, f)
}

func (k *ktLower) stmts(ns []*node) []*stmt {
	var out []*stmt
	for _, n := range ns {
		out = append(out, k.stmt(n)...)
	}
	return out
}

// body lowers a control_structure_body or statements node.
func (k *ktLower) body(n *node) []*stmt {
	if n == nil {
		return nil
	}
	switch k.kind(n) {
	case "control_structure_body":
		var out []*stmt
		for _, c := range k.named(n) {
			out = append(out, k.body(c)...)
		}
		return out
	case "statements":
		return k.stmts(k.named(n))
	}
	return k.stmt(n)
}

func (k *ktLower) stmt(n *node) []*stmt {
	switch kind := k.kind(n); kind {
	case "property_declaration":
		vd := k.firstOfKind(n, "variable_declaration")
		if vd == nil {
			return nil
		}
		name := k.mk(exprName, vd)
		name.name = k.ident(vd)
		name.ty = k.declaredType(vd)
		cs := k.named(n)
		var val *node
		for _, c := range cs {
			if c != vd && k.kind(c) != "binding_pattern_kind" && k.kind(c) != "modifiers" && k.kind(c) != "property_delegate" {
				val = c
			}
		}
		if d := k.firstOfKind(n, "property_delegate"); d != nil {
			if dc := k.named(d); len(dc) > 0 {
				val = dc[0]
			}
		}
		if val == nil {
			if name.ty != "" {
				return []*stmt{{kind: stmtAssign, pos: k.pos(n), lhs: []*expr{name}}}
			}
			return nil
		}
		return []*stmt{{kind: stmtAssign, pos: k.pos(n), lhs: []*expr{name}, rhs: k.expr(val)}}
	case "assignment":
		cs := k.named(n)
		if len(cs) < 2 {
			return nil
		}
		target, value := cs[0], cs[len(cs)-1]
		s := &stmt{kind: stmtAssign, pos: k.pos(n), rhs: k.expr(value), lhs: []*expr{k.target(target)}}
		s.aug = strings.TrimSpace(string(k.src[target.EndByte():value.StartByte()])) != "="
		return []*stmt{s}
	case "jump_expression":
		t := strings.TrimSpace(k.text(n))
		switch {
		case strings.HasPrefix(t, "return"):
			s := &stmt{kind: stmtReturn, pos: k.pos(n)}
			if cs := k.named(n); len(cs) > 0 {
				s.rhs = k.expr(cs[len(cs)-1])
			}
			return []*stmt{s}
		case strings.HasPrefix(t, "break"), strings.HasPrefix(t, "continue"):
			return []*stmt{{kind: stmtJump, pos: k.pos(n), loop: true}}
		}
		return []*stmt{{kind: stmtJump, pos: k.pos(n)}}
	case "if_expression":
		s := &stmt{kind: stmtIf, pos: k.pos(n), cond: k.expr(k.field(n, "condition")), then: k.body(k.field(n, "consequence"))}
		if alt := k.field(n, "alternative"); alt != nil {
			s.els = k.body(alt)
		}
		return []*stmt{s}
	case "for_statement":
		cs := k.named(n)
		if len(cs) < 3 {
			return nil
		}
		name := k.mk(exprName, cs[0])
		name.name = k.ident(cs[0])
		return []*stmt{{kind: stmtLoop, pos: k.pos(n), lhs: []*expr{name}, rhs: k.expr(cs[1]), then: k.body(cs[len(cs)-1])}}
	case "while_statement", "do_while_statement":
		var arm []*stmt
		for _, c := range k.named(n) {
			if k.kind(c) == "control_structure_body" {
				arm = k.body(c)
			}
		}
		return []*stmt{{kind: stmtBranch, pos: k.pos(n), arms: [][]*stmt{arm}}}
	case "when_expression":
		s := &stmt{kind: stmtBranch, pos: k.pos(n)}
		for _, e := range k.named(n) {
			if k.kind(e) == "when_entry" {
				s.arms = append(s.arms, k.body(k.firstOfKind(e, "control_structure_body")))
			}
		}
		return []*stmt{s}
	case "try_expression":
		s := &stmt{kind: stmtBranch, pos: k.pos(n)}
		for _, c := range k.named(n) {
			switch k.kind(c) {
			case "statements":
				s.arms = append(s.arms, k.body(c))
			case "catch_block", "finally_block":
				s.arms = append(s.arms, k.body(k.firstOfKind(c, "statements")))
			}
		}
		return []*stmt{s}
	case "function_declaration":
		k.function(n, k.class)
		return nil
	case "class_declaration", "object_declaration":
		k.classDecl(n)
		return nil
	case "statements":
		return k.stmts(k.named(n))
	case "control_structure_body":
		return k.body(n)
	}
	if e := k.expr(n); e != nil {
		return []*stmt{{kind: stmtExpr, pos: k.pos(n), rhs: e}}
	}
	return nil
}

// target lowers the left side of an assignment.
func (k *ktLower) target(n *node) *expr {
	if k.kind(n) != "directly_assignable_expression" {
		return k.expr(n)
	}
	cs := k.named(n)
	if len(cs) == 0 {
		e := k.mk(exprName, n)
		e.name = k.text(n)
		return e
	}
	base := k.expr(cs[0])
	for _, suf := range cs[1:] {
		switch k.kind(suf) {
		case "navigation_suffix":
			m := k.mk(exprMember, suf)
			m.x, m.name = base, strings.TrimPrefix(k.text(suf), ".")
			m.name = strings.TrimPrefix(m.name, "?.")
			base = m
		case "indexing_suffix":
			ix := k.mk(exprIndex, suf)
			ix.x = base
			for _, a := range k.named(suf) {
				ix.args = append(ix.args, k.expr(a))
			}
			base = k.constKey(ix)
		}
	}
	return base
}

func (k *ktLower) constKey(e *expr) *expr {
	if len(e.args) == 1 && e.args[0].kind == exprStr {
		return &expr{kind: exprMember, pos: e.pos, x: e.x, name: e.args[0].str}
	}
	return e
}

func (k *ktLower) operator(n *node) string {
	cs := k.named(n)
	if len(cs) < 2 {
		return ""
	}
	return strings.TrimSpace(string(k.src[cs[0].EndByte():cs[1].StartByte()]))
}

func (k *ktLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch kind := k.kind(n); kind {
	case "simple_identifier", "this_expression", "super_expression":
		e := k.mk(exprName, n)
		e.name = k.text(n)
		if kind == "this_expression" {
			e.name = "this"
		}
		return e
	case "navigation_expression":
		cs := k.named(n)
		if len(cs) < 2 {
			break
		}
		base := k.expr(cs[0])
		for _, suf := range cs[1:] {
			m := k.mk(exprMember, suf)
			m.x = base
			m.name = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(k.text(suf)), "?"), ".")
			base = m
		}
		return base
	case "call_expression":
		return k.call(n)
	case "string_literal", "multiline_string_literal":
		var subs []*expr
		var text strings.Builder
		for _, c := range k.named(n) {
			switch k.kind(c) {
			case "interpolated_identifier":
				e := k.mk(exprName, c)
				e.name = k.text(c)
				subs = append(subs, e)
			case "interpolated_expression":
				for _, x := range k.named(c) {
					subs = append(subs, k.expr(x))
				}
			case "interpolation":
				for _, x := range k.named(c) {
					subs = append(subs, k.expr(x))
				}
			case "string_content":
				text.WriteString(k.text(c))
			}
		}
		if len(subs) == 0 {
			e := k.mk(exprStr, n)
			e.str = text.String()
			return e
		}
		e := k.mk(exprConcat, n)
		e.args = subs
		return e
	case "integer_literal", "real_literal", "boolean_literal", "null_literal", "character_literal", "long_literal", "hex_literal":
		e := k.mk(exprNum, n)
		e.str = k.text(n)
		return e
	case "additive_expression":
		cs := k.named(n)
		if len(cs) == 2 {
			l, r := k.expr(cs[0]), k.expr(cs[1])
			if k.operator(n) == "-" {
				return k.bin(n, "-", l, r)
			}
			e := k.mk(exprConcat, n)
			e.args = []*expr{l, r}
			return e
		}
	case "multiplicative_expression":
		if cs := k.named(n); len(cs) == 2 {
			return k.bin(n, k.operator(n), k.expr(cs[0]), k.expr(cs[1]))
		}
	case "comparison_expression", "equality_expression":
		if cs := k.named(n); len(cs) == 2 {
			return k.bin(n, k.operator(n), k.expr(cs[0]), k.expr(cs[1]))
		}
	case "conjunction_expression":
		if cs := k.named(n); len(cs) == 2 {
			e := k.mk(exprAnd, n)
			e.args = []*expr{k.expr(cs[0]), k.expr(cs[1])}
			return e
		}
	case "disjunction_expression", "elvis_expression":
		if cs := k.named(n); len(cs) == 2 {
			e := k.mk(exprOr, n)
			e.args = []*expr{k.expr(cs[0]), k.expr(cs[1])}
			return e
		}
	case "prefix_expression":
		if strings.HasPrefix(strings.TrimSpace(k.text(n)), "!") {
			if cs := k.named(n); len(cs) > 0 {
				e := k.mk(exprNot, n)
				e.x = k.expr(cs[len(cs)-1])
				return e
			}
		}
	case "postfix_expression", "as_expression", "parenthesized_expression", "check_expression", "annotated_expression", "spread_expression":
		if cs := k.named(n); len(cs) > 0 {
			return k.expr(cs[0])
		}
	case "indexing_expression":
		cs := k.named(n)
		if len(cs) >= 2 {
			ix := k.mk(exprIndex, n)
			ix.x = k.expr(cs[0])
			for _, a := range k.named(cs[1]) {
				ix.args = append(ix.args, k.expr(a))
			}
			return k.constKey(ix)
		}
	case "if_expression":
		return k.cond(n, k.expr(k.field(n, "condition")), k.exprBody(k.field(n, "consequence")), k.exprBody(k.field(n, "alternative")))
	case "when_expression":
		e := k.mk(exprOther, n)
		for _, en := range k.named(n) {
			if k.kind(en) == "when_entry" {
				if x := k.exprBody(k.firstOfKind(en, "control_structure_body")); x != nil {
					e.args = append(e.args, x)
				}
			}
		}
		return e
	case "lambda_literal":
		e := k.mk(exprLambda, n)
		f := &funcIR{pos: k.pos(n)}
		if lp := k.firstOfKind(n, "lambda_parameters"); lp != nil {
			for _, v := range k.named(lp) {
				f.params = append(f.params, param{name: k.ident(v)})
			}
		} else {
			f.params = []param{{name: "it"}}
		}
		if st := k.firstOfKind(n, "statements"); st != nil {
			body := k.stmts(k.named(st))
			if len(body) > 0 && body[len(body)-1].kind == stmtExpr {
				body[len(body)-1].kind = stmtReturn
			}
			f.body = body
		}
		e.fn = f
		return e
	}
	e := k.mk(exprOther, n)
	for _, c := range k.named(n) {
		if x := k.expr(c); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

// exprBody is the value of a control_structure_body used as an expression.
func (k *ktLower) exprBody(n *node) *expr {
	if n == nil {
		return nil
	}
	cs := k.named(n)
	if len(cs) == 0 {
		return nil
	}
	last := cs[len(cs)-1]
	if k.kind(last) == "statements" {
		if ss := k.named(last); len(ss) > 0 {
			return k.expr(ss[len(ss)-1])
		}
		return nil
	}
	return k.expr(last)
}

func (k *ktLower) call(n *node) *expr {
	cs := k.named(n)
	if len(cs) == 0 {
		return k.mk(exprOther, n)
	}
	callee := cs[0]
	e := k.mk(exprCall, n)
	e.x = k.expr(callee)
	if e.x == nil {
		e.x = k.mk(exprOther, n)
	}
	// File(path) and Foo(x) with a capitalized name are constructors.
	if e.x.kind == exprName && e.x.name != "" && e.x.name[0] >= 'A' && e.x.name[0] <= 'Z' {
		e.kind = exprNew
	}
	for _, suf := range cs[1:] {
		if k.kind(suf) != "call_suffix" {
			continue
		}
		for _, a := range k.named(suf) {
			switch k.kind(a) {
			case "value_arguments":
				for _, va := range k.named(a) {
					parts := k.named(va)
					if len(parts) == 0 {
						continue
					}
					name := ""
					val := parts[len(parts)-1]
					if len(parts) == 2 && k.kind(parts[0]) == "simple_identifier" {
						name = k.text(parts[0])
					}
					e.args = append(e.args, k.expr(val))
					e.kw = append(e.kw, name)
				}
			case "annotated_lambda":
				for _, lam := range k.named(a) {
					e.args = append(e.args, k.expr(lam))
					e.kw = append(e.kw, "")
				}
			}
		}
	}
	// allowed.contains(x), s.startsWith(p), String.format(...)
	if e.x.kind == exprMember {
		switch e.x.name {
		case "contains":
			if len(e.args) == 1 {
				in := k.mk(exprIn, n)
				in.x, in.args = e.x.x, []*expr{e.args[0]}
				return withWeakAllow(in, k.weakAllow(k.pos(n), k.text(callee), k.text(n)))
			}
		case "startsWith":
			if len(e.args) == 1 {
				in := k.mk(exprIn, n)
				in.x, in.args = e.args[0], []*expr{e.x.x}
				return withWeakAllow(in, k.weakAllow(k.pos(n), k.text(callee), k.text(n)))
			}
		case "format", "joinToString", "plus":
			c := k.mk(exprConcat, n)
			c.args = append([]*expr{e.x.x}, e.args...)
			return c
		}
	}
	return e
}
