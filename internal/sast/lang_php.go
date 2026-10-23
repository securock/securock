package sast

import (
	"strings"
)

func phpSinks() map[string]sink {
	m := map[string]sink{
		"mysqli_query": {kind: kSQL, args: []int{1}}, "mysqli_multi_query": {kind: kSQL, args: []int{1}},
		"mysqli_real_query": {kind: kSQL, args: []int{1}}, "mysql_query": {kind: kSQL, args: []int{0}},
		"pg_query": {kind: kSQL, args: []int{1}}, "sqlite_query": {kind: kSQL, args: []int{1}},
		"?.query": {kind: kSQL, args: []int{0}, recv: phpDB}, "?.exec": {kind: kSQL, args: []int{0}, recv: phpDB},
		"?.prepare": {kind: kSQL, args: []int{0}, recv: phpDB}, "?.multi_query": {kind: kSQL, args: []int{0}},
		"?.real_query": {kind: kSQL, args: []int{0}}, "?.whereRaw": {kind: kSQL, args: []int{0}},
		"?.orderByRaw": {kind: kSQL, args: []int{0}}, "?.selectRaw": {kind: kSQL, args: []int{0}},
		"?.havingRaw": {kind: kSQL, args: []int{0}}, "?.groupByRaw": {kind: kSQL, args: []int{0}},
		"Illuminate.Support.Facades.DB.select": {kind: kSQL, args: []int{0}}, "Illuminate.Support.Facades.DB.statement": {kind: kSQL, args: []int{0}},
		"Illuminate.Support.Facades.DB.raw": {kind: kSQL, args: []int{0}}, "Illuminate.Support.Facades.DB.unprepared": {kind: kSQL, args: []int{0}},

		"system": {kind: kCmd, args: []int{0}}, "exec": {kind: kCmd, args: []int{0}}, "shell_exec": {kind: kCmd, args: []int{0}},
		"passthru": {kind: kCmd, args: []int{0}}, "popen": {kind: kCmd, args: []int{0}}, "proc_open": {kind: kCmd, args: []int{0}},
		"pcntl_exec": {kind: kCmd, args: []int{0}},

		"eval": {kind: kCode, args: []int{0}}, "assert": {kind: kCode, args: []int{0}}, "create_function": {kind: kCode, args: []int{1}},
		"unserialize": {kind: kDeser, args: []int{0}},
		"include":     {kind: kPath, args: []int{0}},

		"file_get_contents": {kind: kPath, args: []int{0}}, "file_put_contents": {kind: kPath, args: []int{0}},
		"fopen": {kind: kPath, args: []int{0}}, "readfile": {kind: kPath, args: []int{0}}, "file": {kind: kPath, args: []int{0}},
		"unlink": {kind: kPath, args: []int{0}}, "rmdir": {kind: kPath, args: []int{0}}, "mkdir": {kind: kPath, args: []int{0}},
		"copy": {kind: kPath, args: []int{0, 1}}, "rename": {kind: kPath, args: []int{0, 1}},
		"move_uploaded_file": {kind: kPath, args: []int{1}}, "scandir": {kind: kPath, args: []int{0}},
		"opendir": {kind: kPath, args: []int{0}}, "highlight_file": {kind: kPath, args: []int{0}}, "show_source": {kind: kPath, args: []int{0}},

		"curl_init": {kind: kSSRF, args: []int{0}}, "fsockopen": {kind: kSSRF, args: []int{0}}, "get_headers": {kind: kSSRF, args: []int{0}},
		"SoapClient": {kind: kSSRF, args: []int{0}},

		"echo": {kind: kXSS, args: []int{0}, rest: true}, "print": {kind: kXSS, args: []int{0}}, "printf": {kind: kXSS, args: []int{0}, rest: true},
		"header": {kind: kRedirect, args: []int{0}},
	}
	return m
}

var phpDB = []string{"db", "pdo", "conn", "connection", "mysqli", "dbh", "database", "link", "mysql", "this"}

var phpSuperglobal = func() map[string]map[string]string {
	any := map[string]string{"*": "request data"}
	return map[string]map[string]string{
		"_GET": any, "_POST": any, "_REQUEST": any, "_COOKIE": any, "_FILES": any, "argv": {"*": "command-line arguments"},
		"_SERVER": {
			"REQUEST_URI": "request URL", "QUERY_STRING": "request query", "PATH_INFO": "request path", "PHP_SELF": "request path",
			"HTTP_HOST": "request host", "HTTP_REFERER": "request header", "HTTP_USER_AGENT": "request header",
			"HTTP_X_FORWARDED_FOR": "request header", "HTTP_COOKIE": "request header", "HTTP_ACCEPT_LANGUAGE": "request header",
		},
		"request": {"input": "request data", "get": "request data", "post": "request data", "query": "request query",
			"all": "request data", "cookie": "request cookie", "header": "request header", "file": "uploaded file",
			"route": "request path", "getContent": "request body", "json": "request body", "only": "request data",
			"request": "request body", "headers": "request header", "cookies": "request cookie", "attributes": "request path"},
	}
}()

var phpSpec = &langSpec{
	name:  "php",
	sinks: phpSinks(),
	sanitizers: map[string]kind{
		"intval": kAll, "floatval": kAll, "doubleval": kAll, "boolval": kAll, "abs": kAll, "count": kAll, "strlen": kAll,
		"htmlspecialchars": kXSS, "htmlentities": kXSS, "strip_tags": kXSS, "e": kXSS,
		"escapeshellarg": kCmd, "escapeshellcmd": kCmd, "basename": kPath,
		"urlencode": kXSS | kPath | kRedirect | kSSRF, "rawurlencode": kXSS | kPath | kRedirect | kSSRF,
		"mysqli_real_escape_string": kSQL, "mysql_real_escape_string": kSQL, "pg_escape_string": kSQL, "?.quote": kSQL,
		"?.real_escape_string": kSQL, "md5": kAll, "sha1": kAll, "hash": kAll, "crc32": kAll,
	},
	sourceRoots: phpSuperglobal,
	self:        map[string]bool{"this": true},
	shells:      map[string]bool{},
	mutators:    map[string]bool{"add": true, "push": true, "append": true},
	simpleTypes: map[string]string{"DB": "Illuminate.Support.Facades.DB"},
	builtins: func() map[string]bool {
		m := map[string]bool{}
		for k := range phpSinks() {
			if !strings.HasPrefix(k, "?") && !strings.Contains(k, ".") {
				m[k] = true
			}
		}
		for k := range map[string]bool{"intval": true, "floatval": true, "htmlspecialchars": true, "htmlentities": true, "strip_tags": true,
			"escapeshellarg": true, "escapeshellcmd": true, "basename": true, "urlencode": true, "rawurlencode": true,
			"mysqli_real_escape_string": true, "md5": true, "sha1": true, "hash": true, "count": true, "strlen": true, "abs": true, "boolval": true} {
			m[k] = true
		}
		return m
	}(),
}

func init() { frontends["php"] = &frontend{spec: phpSpec, lower: lowerPHP} }

type phpLower struct {
	*lowering
	class string
}

func lowerPHP(l *lowering) *module {
	p := &phpLower{lowering: l}
	l.mod.top = p.stmts(l.named(l.root))
	p.constants(l.root)
	return l.mod
}

func (p *phpLower) stmts(ns []*node) []*stmt {
	var out []*stmt
	for _, n := range ns {
		out = append(out, p.stmt(n)...)
	}
	return out
}

func (p *phpLower) block(n *node) []*stmt {
	if n == nil {
		return nil
	}
	if p.kind(n) == "compound_statement" || p.kind(n) == "colon_block" {
		return p.stmts(p.named(n))
	}
	return p.stmt(n)
}

func phpName(s string) string { return strings.TrimPrefix(s, "$") }

func (p *phpLower) stmt(n *node) []*stmt {
	switch k := p.kind(n); k {
	case "expression_statement":
		var out []*stmt
		for _, c := range p.named(n) {
			if p.kind(c) == "function_call_expression" {
				if fn := p.field(c, "function"); fn != nil && (p.text(fn) == "die" || p.text(fn) == "exit") {
					out = append(out, &stmt{kind: stmtJump, pos: p.pos(c)})
					continue
				}
			}
			if kk := p.kind(c); kk == "assignment_expression" || kk == "augmented_assignment_expression" {
				out = append(out, p.assignment(c))
			} else {
				out = append(out, &stmt{kind: stmtExpr, pos: p.pos(c), rhs: p.expr(c)})
			}
		}
		return out
	case "echo_statement":
		call := p.mk(exprCall, n)
		fn := p.mk(exprName, n)
		fn.name = "echo"
		call.x = fn
		for _, c := range p.named(n) {
			call.args = append(call.args, p.expr(c))
			call.kw = append(call.kw, "")
		}
		return []*stmt{{kind: stmtExpr, pos: p.pos(n), rhs: call}}
	case "return_statement":
		s := &stmt{kind: stmtReturn, pos: p.pos(n)}
		if cs := p.named(n); len(cs) > 0 {
			s.rhs = p.expr(cs[0])
		}
		return []*stmt{s}
	case "throw_expression", "exit_statement":
		return []*stmt{{kind: stmtJump, pos: p.pos(n)}}
	case "break_statement", "continue_statement":
		return []*stmt{{kind: stmtJump, pos: p.pos(n), loop: true}}
	case "if_statement":
		s := &stmt{kind: stmtIf, pos: p.pos(n), cond: p.expr(p.field(n, "condition")), then: p.block(p.field(n, "body"))}
		for _, c := range p.named(n) {
			switch p.kind(c) {
			case "else_clause":
				s.els = append(s.els, p.block(p.field(c, "body"))...)
			case "else_if_clause":
				s.els = append(s.els, &stmt{kind: stmtIf, pos: p.pos(c), cond: p.expr(p.field(c, "condition")), then: p.block(p.field(c, "body"))})
			}
		}
		return []*stmt{s}
	case "foreach_statement":
		cs := p.named(n)
		s := &stmt{kind: stmtLoop, pos: p.pos(n), then: p.block(p.field(n, "body"))}
		if len(cs) > 0 {
			s.rhs = p.expr(cs[0])
		}
		if len(cs) > 1 {
			if p.kind(cs[1]) == "pair" {
				for _, v := range p.named(cs[1]) {
					s.lhs = append(s.lhs, p.expr(v))
				}
			} else {
				s.lhs = []*expr{p.expr(cs[1])}
			}
		}
		return []*stmt{s}
	case "for_statement", "while_statement", "do_statement":
		return []*stmt{{kind: stmtBranch, pos: p.pos(n), arms: [][]*stmt{p.block(p.field(n, "body"))}}}
	case "switch_statement":
		s := &stmt{kind: stmtBranch, pos: p.pos(n)}
		if b := p.field(n, "body"); b != nil {
			for _, c := range p.named(b) {
				s.arms = append(s.arms, p.stmts(p.named(c)))
			}
		}
		return []*stmt{s}
	case "try_statement":
		s := &stmt{kind: stmtBranch, pos: p.pos(n)}
		s.arms = append(s.arms, p.block(p.field(n, "body")))
		for _, c := range p.named(n) {
			if kk := p.kind(c); kk == "catch_clause" || kk == "finally_clause" {
				s.arms = append(s.arms, p.block(p.field(c, "body")))
			}
		}
		return []*stmt{s}
	case "compound_statement":
		return []*stmt{{kind: stmtBranch, pos: p.pos(n), arms: [][]*stmt{p.stmts(p.named(n))}}}
	case "function_definition":
		p.function(n, "")
	case "class_declaration", "trait_declaration", "interface_declaration":
		p.classDecl(n)
	case "namespace_use_declaration":
		for _, c := range p.named(n) {
			if p.kind(c) == "namespace_use_clause" {
				full := strings.ReplaceAll(strings.TrimSpace(p.text(c)), "\\", ".")
				alias := ""
				if i := strings.LastIndex(full, " as "); i >= 0 {
					alias = strings.TrimSpace(full[i+4:])
					full = strings.TrimSpace(full[:i])
				}
				full = strings.TrimPrefix(full, ".")
				if alias == "" {
					alias = full[strings.LastIndex(full, ".")+1:]
				}
				p.mod.imports[alias] = full
			}
		}
	case "namespace_definition":
		return p.stmts(p.named(p.field(n, "body")))
	}
	return nil
}

func (p *phpLower) assignment(n *node) *stmt {
	s := &stmt{kind: stmtAssign, pos: p.pos(n), rhs: p.expr(p.field(n, "right")), aug: p.kind(n) == "augmented_assignment_expression"}
	s.lhs = []*expr{p.expr(p.field(n, "left"))}
	if l := p.field(n, "left"); l != nil && (p.kind(l) == "list_literal" || p.kind(l) == "array_creation_expression") {
		s.lhs = nil
		for _, c := range p.named(l) {
			s.lhs = append(s.lhs, p.expr(c))
		}
	}
	return s
}

func (p *phpLower) classDecl(n *node) {
	name := p.text(p.field(n, "name"))
	prev := p.class
	p.class = name
	defer func() { p.class = prev }()
	for _, c := range p.named(n) {
		if p.kind(c) == "base_clause" || p.kind(c) == "class_interface_clause" {
			for _, b := range p.named(c) {
				p.mod.supers[name] = append(p.mod.supers[name], p.text(b))
			}
		}
	}
	for _, m := range p.named(p.field(n, "body")) {
		switch p.kind(m) {
		case "method_declaration":
			p.function(m, name)
		case "property_declaration":
			for _, pe := range p.named(m) {
				if p.kind(pe) == "property_element" {
					// typed properties: private PDO $db
					if t := p.field(m, "type"); t != nil {
						if p.mod.fields[name] == nil {
							p.mod.fields[name] = map[string]string{}
						}
						p.mod.fields[name][phpName(p.text(p.field(pe, "name")))] = strings.TrimPrefix(p.text(t), "?")
					}
				}
			}
		}
	}
}

func (p *phpLower) function(n *node, class string) {
	f := &funcIR{name: p.text(p.field(n, "name")), class: class, pos: p.pos(n)}
	if f.name == "__construct" {
		f.name = "<init>"
	}
	if ps := p.field(n, "parameters"); ps != nil {
		for _, c := range p.named(ps) {
			pr := param{name: phpName(p.text(p.field(c, "name")))}
			if t := p.field(c, "type"); t != nil {
				pr.ty = strings.TrimPrefix(p.text(t), "?")
			}
			f.params = append(f.params, pr)
		}
	}
	f.body = p.block(p.field(n, "body"))
	p.mod.funcs = append(p.mod.funcs, f)
}

func (p *phpLower) args(n *node, into *expr) {
	for _, a := range p.named(n) {
		x := a
		if p.kind(a) == "argument" {
			if cs := p.named(a); len(cs) > 0 {
				x = cs[len(cs)-1]
			}
		}
		into.args = append(into.args, p.expr(x))
		into.kw = append(into.kw, "")
	}
}

func (p *phpLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch k := p.kind(n); k {
	case "variable_name":
		e := p.mk(exprName, n)
		e.name = phpName(p.text(n))
		return e
	case "name", "qualified_name":
		e := p.mk(exprName, n)
		e.name = strings.ReplaceAll(strings.TrimPrefix(p.text(n), "\\"), "\\", ".")
		return e
	case "member_access_expression", "nullsafe_member_access_expression":
		e := p.mk(exprMember, n)
		e.x = p.expr(p.field(n, "object"))
		e.name = phpName(p.text(p.field(n, "name")))
		return e
	case "scoped_property_access_expression", "class_constant_access_expression":
		cs := p.named(n)
		e := p.mk(exprMember, n)
		if len(cs) >= 2 {
			e.x, e.name = p.expr(cs[0]), phpName(p.text(cs[len(cs)-1]))
			if p.kind(cs[0]) == "relative_scope" {
				e.x = p.mk(exprName, cs[0])
				e.x.name = strings.TrimSpace(p.text(cs[0]))
			}
		}
		return e
	case "subscript_expression":
		cs := p.named(n)
		if len(cs) < 2 {
			break
		}
		e := p.mk(exprIndex, n)
		e.x = p.expr(cs[0])
		e.args = []*expr{p.expr(cs[1])}
		if p.kind(cs[1]) == "string" {
			m := p.mk(exprMember, n)
			m.x, m.name = e.x, p.strValue(cs[1])
			return m
		}
		return e
	case "function_call_expression":
		e := p.mk(exprCall, n)
		e.x = p.expr(p.field(n, "function"))
		if e.x == nil {
			e.x = p.mk(exprOther, n)
		}
		p.args(p.field(n, "arguments"), e)
		return p.callShape(n, e)
	case "member_call_expression", "nullsafe_member_call_expression":
		e := p.mk(exprCall, n)
		m := p.mk(exprMember, n)
		m.x = p.expr(p.field(n, "object"))
		m.name = p.text(p.field(n, "name"))
		e.x = m
		p.args(p.field(n, "arguments"), e)
		return e
	case "scoped_call_expression":
		e := p.mk(exprCall, n)
		m := p.mk(exprMember, n)
		m.x = p.expr(p.field(n, "scope"))
		m.name = p.text(p.field(n, "name"))
		e.x = m
		p.args(p.field(n, "arguments"), e)
		return e
	case "object_creation_expression":
		e := p.mk(exprNew, n)
		for _, c := range p.named(n) {
			if kk := p.kind(c); kk == "name" || kk == "qualified_name" {
				e.x = p.expr(c)
			} else if kk == "arguments" {
				p.args(c, e)
			}
		}
		if e.x == nil {
			e.x = p.mk(exprOther, n)
		}
		return e
	case "string", "nowdoc", "heredoc":
		return p.str(n)
	case "encapsed_string":
		return p.encapsed(n)
	case "integer", "float", "boolean", "null":
		e := p.mk(exprNum, n)
		e.str = p.text(n)
		return e
	case "binary_expression":
		l, r := p.expr(p.field(n, "left")), p.expr(p.field(n, "right"))
		op := strings.TrimSpace(string(p.src[p.field(n, "left").EndByte():p.field(n, "right").StartByte()]))
		switch op {
		case ".":
			e := p.mk(exprConcat, n)
			e.args = []*expr{l, r}
			return e
		case "&&", "and":
			e := p.mk(exprAnd, n)
			e.args = []*expr{l, r}
			return e
		case "||", "or", "??":
			e := p.mk(exprOr, n)
			e.args = []*expr{l, r}
			return e
		case "==", "===", "!=", "!==", "<", ">", "<=", ">=", "<>":
			return p.bin(n, op, l, r)
		}
		return p.other(n, l, r)
	case "unary_op_expression":
		cs := p.named(n)
		if len(cs) > 0 && strings.HasPrefix(strings.TrimSpace(p.text(n)), "!") {
			e := p.mk(exprNot, n)
			e.x = p.expr(cs[len(cs)-1])
			return e
		}
	case "cast_expression":
		t := strings.ToLower(p.text(p.field(n, "type")))
		if strings.Contains(t, "int") || strings.Contains(t, "float") || strings.Contains(t, "bool") || strings.Contains(t, "double") {
			e := p.mk(exprNum, n)
			return e
		}
		if cs := p.named(n); len(cs) > 0 {
			return p.expr(cs[len(cs)-1])
		}
	case "parenthesized_expression", "reference_assignment_expression":
		if cs := p.named(n); len(cs) > 0 {
			return p.expr(cs[len(cs)-1])
		}
	case "assignment_expression":
		return p.expr(p.field(n, "right"))
	case "conditional_expression":
		return p.cond(n, p.expr(p.field(n, "condition")), p.expr(p.field(n, "body")), p.expr(p.field(n, "alternative")))
	case "arrow_function", "anonymous_function":
		e := p.mk(exprLambda, n)
		f := &funcIR{pos: p.pos(n)}
		if ps := p.field(n, "parameters"); ps != nil {
			for _, c := range p.named(ps) {
				f.params = append(f.params, param{name: phpName(p.text(p.field(c, "name")))})
			}
		}
		if b := p.field(n, "body"); b != nil {
			if p.kind(b) == "compound_statement" {
				f.body = p.block(b)
			} else {
				f.body = []*stmt{{kind: stmtReturn, pos: p.pos(b), rhs: p.expr(b)}}
			}
		}
		e.fn = f
		return e
	case "shell_command_expression":
		call := p.mk(exprCall, n)
		fn := p.mk(exprName, n)
		fn.name = "shell_exec"
		call.x = fn
		call.args = []*expr{p.encapsed(n)}
		call.kw = []string{""}
		return call
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		call := p.mk(exprCall, n)
		fn := p.mk(exprName, n)
		fn.name = "include"
		call.x = fn
		if cs := p.named(n); len(cs) > 0 {
			call.args = []*expr{p.expr(cs[0])}
			call.kw = []string{""}
		}
		return call
	case "print_intrinsic":
		call := p.mk(exprCall, n)
		fn := p.mk(exprName, n)
		fn.name = "print"
		call.x = fn
		if cs := p.named(n); len(cs) > 0 {
			call.args = []*expr{p.expr(cs[0])}
			call.kw = []string{""}
		}
		return call
	}
	e := p.mk(exprOther, n)
	for _, c := range p.named(n) {
		if x := p.expr(c); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

// callShape turns validators into the membership form the engine understands.
func (p *phpLower) callShape(n *node, e *expr) *expr {
	if e.x.kind != exprName {
		return e
	}
	switch e.x.name {
	case "preg_match":
		if len(e.args) >= 2 && e.args[0].kind == exprStr && strictLiteral(e.args[0].str, phpDelim(e.args[0].str), false) {
			return guardOf(p.pos(n), e.args[1])
		}
	case "str_starts_with":
		if len(e.args) == 2 {
			in := p.mk(exprIn, n)
			in.x, in.args = e.args[1], []*expr{e.args[0]}
			return in
		}
	case "in_array":
		if len(e.args) >= 2 {
			in := p.mk(exprIn, n)
			in.x, in.args = e.args[1], []*expr{e.args[0]}
			return in
		}
	case "is_numeric", "ctype_digit", "ctype_alnum", "is_int", "ctype_alpha":
		if len(e.args) == 1 {
			in := p.mk(exprIn, n)
			in.x, in.args = p.mk(exprNum, n), e.args
			return in
		}
	case "sprintf", "vsprintf", "implode", "join", "str_replace", "substr", "trim", "strtolower", "strtoupper":
		c := p.mk(exprConcat, n)
		c.args = e.args
		return c
	}
	return e
}

func (p *phpLower) strValue(n *node) string {
	var b strings.Builder
	for _, c := range p.named(n) {
		if p.kind(c) == "string_content" || p.kind(c) == "string_value" {
			b.WriteString(p.text(c))
		}
	}
	return b.String()
}

func (p *phpLower) str(n *node) *expr {
	e := p.mk(exprStr, n)
	e.str = p.strValue(n)
	return e
}

// encapsed is a double-quoted string: plain text with embedded variables.
func (p *phpLower) encapsed(n *node) *expr {
	var subs []*expr
	for _, c := range p.named(n) {
		switch p.kind(c) {
		case "string_content", "escape_sequence", "string_value":
		default:
			if x := p.expr(c); x != nil {
				subs = append(subs, x)
			}
		}
	}
	if len(subs) == 0 {
		return p.str(n)
	}
	e := p.mk(exprConcat, n)
	e.args = subs
	return e
}

// phpDelim is the delimiter of a PCRE pattern string: the first character.
func phpDelim(pat string) string {
	if pat == "" {
		return ""
	}
	return pat[:1]
}

// constants records define('KEY', '...') and const KEY = '...' as assignments in the
// module's top-level code, where string constants are looked up.
func (p *phpLower) constants(n *node) {
	add := func(at *node, name string, val *node) {
		if val == nil || p.kind(val) != "string" {
			return
		}
		id := p.mk(exprName, at)
		id.name = name
		p.mod.top = append(p.mod.top, &stmt{kind: stmtAssign, pos: p.pos(at), lhs: []*expr{id}, rhs: p.expr(val)})
	}
	switch p.kind(n) {
	case "const_element":
		if cs := p.named(n); len(cs) == 2 {
			add(n, p.text(cs[0]), cs[1])
		}
	case "function_call_expression":
		if p.text(p.field(n, "function")) == "define" {
			if args := p.named(p.field(n, "arguments")); len(args) == 2 {
				k, v := p.named(args[0]), p.named(args[1])
				if len(k) == 1 && len(v) == 1 && p.kind(k[0]) == "string" {
					add(n, strings.Trim(p.text(k[0]), `'"`), v[0])
				}
			}
		}
	}
	for _, c := range p.named(n) {
		p.constants(c)
	}
}
