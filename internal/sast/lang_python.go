package sast

import (
	"strings"
)

var pyRequestRoot = map[string]string{
	"GET": "request parameter", "POST": "request form field", "body": "request body", "COOKIES": "request cookie",
	"META": "request header", "FILES": "uploaded file", "headers": "request header", "args": "request parameter",
	"form": "request form field", "values": "request parameter", "json": "request body", "data": "request body",
	"cookies": "request cookie", "query_params": "request parameter", "path_params": "request parameter",
	"query": "request parameter", "path": "request path", "path_info": "request path", "url": "request URL",
	"get_json": "request body", "get_data": "request body", "stream": "request body", "files": "uploaded file",
	"full_path": "request path", "environ": "request header", "host": "request host",
}

var pyHTTPFns = []string{"get", "post", "put", "delete", "head", "patch", "options"}

func pySinks() map[string]sink {
	m := map[string]sink{
		"os.system": {kind: kCmd, args: []int{0}}, "os.popen": {kind: kCmd, args: []int{0}},
		"subprocess.getoutput": {kind: kCmd, args: []int{0}}, "subprocess.getstatusoutput": {kind: kCmd, args: []int{0}},
		"commands.getoutput": {kind: kCmd, args: []int{0}},
		"eval":               {kind: kCode, args: []int{0}}, "exec": {kind: kCode, args: []int{0}},
		"compile": {kind: kCode, args: []int{0}}, "__import__": {kind: kCode, args: []int{0}},
		"importlib.import_module":      {kind: kCode, args: []int{0}},
		"flask.render_template_string": {kind: kCode, args: []int{0}}, "jinja2.Template": {kind: kCode, args: []int{0}},

		"?.execute": {kind: kSQL, args: []int{0}}, "?.executemany": {kind: kSQL, args: []int{0}},
		"?.executescript": {kind: kSQL, args: []int{0}}, "?.raw": {kind: kSQL, args: []int{0}},
		"sqlalchemy.text": {kind: kSQL, args: []int{0}}, "pandas.read_sql": {kind: kSQL, args: []int{0}},
		"pandas.read_sql_query": {kind: kSQL, args: []int{0}}, "django.db.models.expressions.RawSQL": {kind: kSQL, args: []int{0}},
		"psycopg2.sql.SQL": {kind: kSQL, args: []int{0}},

		"open": {kind: kPath, args: []int{0}}, "os.remove": {kind: kPath, args: []int{0}}, "os.unlink": {kind: kPath, args: []int{0}},
		"os.rmdir": {kind: kPath, args: []int{0}}, "os.mkdir": {kind: kPath, args: []int{0}}, "os.makedirs": {kind: kPath, args: []int{0}},
		"os.listdir": {kind: kPath, args: []int{0}}, "os.rename": {kind: kPath, args: []int{0, 1}},
		"shutil.copy": {kind: kPath, args: []int{0, 1}}, "shutil.move": {kind: kPath, args: []int{0, 1}},
		"shutil.rmtree": {kind: kPath, args: []int{0}}, "flask.send_file": {kind: kPath, args: []int{0}},

		"urllib.request.urlopen": {kind: kSSRF, args: []int{0}}, "urllib.request.Request": {kind: kSSRF, args: []int{0}},
		"requests.request": {kind: kSSRF, args: []int{1}}, "httpx.request": {kind: kSSRF, args: []int{1}},
		"http.client.HTTPConnection": {kind: kSSRF, args: []int{0}}, "http.client.HTTPSConnection": {kind: kSSRF, args: []int{0}},

		"flask.Markup": {kind: kXSS, args: []int{0}}, "markupsafe.Markup": {kind: kXSS, args: []int{0}},
		"django.utils.safestring.mark_safe": {kind: kXSS, args: []int{0}}, "django.http.HttpResponse": {kind: kXSS, args: []int{0}},
		"flask.make_response": {kind: kXSS, args: []int{0}},

		"flask.redirect": {kind: kRedirect, args: []int{0}}, "django.shortcuts.redirect": {kind: kRedirect, args: []int{0}},
		"django.http.HttpResponseRedirect":   {kind: kRedirect, args: []int{0}},
		"fastapi.responses.RedirectResponse": {kind: kRedirect, args: []int{0}},

		"pickle.loads": {kind: kDeser, args: []int{0}}, "pickle.load": {kind: kDeser, args: []int{0}},
		"cPickle.loads": {kind: kDeser, args: []int{0}}, "marshal.loads": {kind: kDeser, args: []int{0}},
		"yaml.load": {kind: kDeser, args: []int{0}}, "yaml.unsafe_load": {kind: kDeser, args: []int{0}},
		"shelve.open": {kind: kDeser, args: []int{0}}, "jsonpickle.decode": {kind: kDeser, args: []int{0}},
		"pandas.read_pickle": {kind: kDeser, args: []int{0}},
	}
	for _, f := range []string{"run", "call", "check_call", "check_output", "Popen"} {
		m["subprocess."+f] = sink{kind: kCmd, args: []int{0}, kwTrue: "shell"}
	}
	for _, f := range pyHTTPFns {
		m["requests."+f] = sink{kind: kSSRF, args: []int{0}}
		m["httpx."+f] = sink{kind: kSSRF, args: []int{0}}
	}
	for _, typ := range []string{"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"} {
		for _, method := range []string{"exists", "is_file", "is_dir", "is_symlink", "stat", "lstat", "open", "readlink"} {
			m[typ+"."+method] = sink{kind: kPath, args: []int{-1}}
		}
	}
	return m
}

var pySpec = &langSpec{
	name:  "py",
	sinks: pySinks(),
	sanitizers: map[string]kind{
		"int": kAll, "float": kAll, "bool": kAll, "len": kAll, "ord": kAll, "hash": kAll,
		"shlex.quote": kCmd, "html.escape": kXSS, "markupsafe.escape": kXSS, "flask.escape": kXSS,
		"django.utils.html.escape": kXSS, "bleach.clean": kXSS, "django.utils.html.strip_tags": kXSS,
		"os.path.basename": kPath, "werkzeug.utils.secure_filename": kPath,
		"urllib.parse.quote": kXSS | kPath | kRedirect | kSSRF, "urllib.parse.quote_plus": kXSS | kPath | kRedirect | kSSRF,
		"uuid.UUID": kAll, "ipaddress.ip_address": kAll, "ipaddress.ip_network": kAll,
		"hashlib.sha256": kAll, "hashlib.md5": kAll, "hashlib.sha1": kAll,
	},
	sourcePrefixes: map[string]string{
		"flask.request": "request data", "sys.argv": "command-line arguments", "input": "console input",
		"django.http.HttpRequest": "request data", "fastapi.Request": "request data",
	},
	sourceRoots: map[string]map[string]string{"request": pyRequestRoot, "req": pyRequestRoot},
	sourceMethods: map[string]string{
		"get_argument": "request parameter", "get_query_argument": "request parameter", "get_body_argument": "request body",
	},
	returns: map[string]string{
		"sqlite3.connect": "sqlite3.Connection", "sqlite3.Connection.cursor": "sqlite3.Cursor",
		"psycopg2.connect": "psycopg2.Connection", "psycopg2.Connection.cursor": "psycopg2.Cursor",
		"pymysql.connect": "pymysql.Connection", "pymysql.Connection.cursor": "pymysql.Cursor",
	},
	mutators: map[string]bool{"append": true, "extend": true, "add": true, "update": true, "insert": true, "setdefault": true, "write": true},
	self:     map[string]bool{"self": true, "cls": true},
	shells:   map[string]bool{},
	builtins: map[string]bool{
		"open": true, "eval": true, "exec": true, "compile": true, "int": true, "float": true, "bool": true,
		"len": true, "ord": true, "hash": true, "input": true, "__import__": true,
	},
}

// configUnknownField marks a ConfigParser that received a value under a key the
// analysis could not determine; get() must then return that value for any key.
const configUnknownField = "\x00config-unknown"

func isConfigParserType(ty string) bool {
	return ty == "configparser.ConfigParser" || ty == "configparser.RawConfigParser"
}

func init() {
	// A ConfigParser round trip stores text on the receiver and hands it back
	// from get(); tracking per section and key keeps known-safe values safe.
	for _, typ := range []string{"configparser.ConfigParser", "configparser.RawConfigParser"} {
		pySpec.returns[typ] = typ
	}
	for _, typ := range []string{"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"} {
		pySpec.returns[typ] = typ
		for _, method := range []string{"joinpath", "with_name", "with_suffix", "absolute", "resolve", "expanduser"} {
			pySpec.returns[typ+"."+method] = typ
		}
	}
	frontends["py"] = &frontend{spec: pySpec, lower: lowerPython}
}

type pyLower struct {
	*lowering
	class string
}

func lowerPython(l *lowering) *module {
	p := &pyLower{lowering: l}
	l.mod.top = p.stmts(l.named(l.root))
	return l.mod
}

func (p *pyLower) stmts(ns []*node) []*stmt {
	var out []*stmt
	for _, n := range ns {
		out = append(out, p.stmt(n)...)
	}
	return out
}

func (p *pyLower) block(n *node) []*stmt {
	if n == nil {
		return nil
	}
	if p.kind(n) == "block" {
		return p.stmts(p.named(n))
	}
	return p.stmt(n)
}

func (p *pyLower) stmt(n *node) []*stmt {
	switch k := p.kind(n); k {
	case "assignment":
		s := &stmt{kind: stmtAssign, pos: p.pos(n), rhs: p.expr(p.field(n, "right"))}
		s.lhs = p.targets(p.field(n, "left"))
		if t := p.field(n, "type"); t != nil && len(s.lhs) == 1 {
			s.lhs[0].ty = p.typeText(t)
		}
		if s.rhs == nil {
			return nil
		}
		return []*stmt{s}
	case "augmented_assignment":
		s := &stmt{kind: stmtAssign, aug: true, pos: p.pos(n), rhs: p.expr(p.field(n, "right"))}
		s.lhs = p.targets(p.field(n, "left"))
		return []*stmt{s}
	case "return_statement":
		s := &stmt{kind: stmtReturn, pos: p.pos(n)}
		if cs := p.named(n); len(cs) > 0 {
			s.rhs = p.expr(cs[0])
		}
		return []*stmt{s}
	case "raise_statement":
		s := &stmt{kind: stmtJump, pos: p.pos(n)}
		if cs := p.named(n); len(cs) > 0 {
			s.rhs = p.expr(cs[0])
		}
		return []*stmt{s}
	case "break_statement", "continue_statement":
		return []*stmt{{kind: stmtJump, pos: p.pos(n), loop: true, next: k == "continue_statement"}}
	case "if_statement":
		return []*stmt{p.ifStmt(n)}
	case "for_statement":
		s := &stmt{kind: stmtLoop, pos: p.pos(n), rhs: p.expr(p.field(n, "right")), then: p.block(p.field(n, "body"))}
		s.lhs = p.targets(p.field(n, "left"))
		return []*stmt{s}
	case "while_statement":
		return []*stmt{{kind: stmtLoop, pos: p.pos(n), then: p.block(p.field(n, "body")), cond: p.expr(p.field(n, "condition"))}}
	case "try_statement":
		s := &stmt{kind: stmtBranch, pos: p.pos(n)}
		for _, c := range p.named(n) {
			switch p.kind(c) {
			case "block":
				s.arms = append(s.arms, p.block(c))
			case "except_clause", "except_group_clause", "else_clause", "finally_clause":
				for _, cc := range p.named(c) {
					if p.kind(cc) == "block" {
						s.arms = append(s.arms, p.block(cc))
					}
				}
			}
		}
		return []*stmt{s}
	case "with_statement":
		var out []*stmt
		if wc := p.firstOfKind(n, "with_clause"); wc != nil {
			for _, item := range p.named(wc) {
				v := p.field(item, "value")
				if v == nil {
					continue
				}
				if p.kind(v) == "as_pattern" {
					cs := p.named(v)
					if len(cs) == 2 {
						s := &stmt{kind: stmtAssign, pos: p.pos(v), rhs: p.expr(cs[0])}
						s.lhs = p.targets(p.field(v, "alias"))
						out = append(out, s)
						continue
					}
				}
				out = append(out, &stmt{kind: stmtExpr, pos: p.pos(v), rhs: p.expr(v)})
			}
		}
		out = append(out, &stmt{kind: stmtBranch, pos: p.pos(n), arms: [][]*stmt{p.block(p.field(n, "body"))}})
		return out
	case "function_definition":
		p.function(n, false)
	case "decorated_definition":
		def := p.field(n, "definition")
		if def == nil {
			return nil
		}
		switch p.kind(def) {
		case "function_definition":
			before := len(p.mod.funcs)
			p.function(def, p.decorators(n), p.htmlRoute(n))
			if p.csrfExempt(n) && len(p.mod.funcs) > before {
				f := p.mod.funcs[len(p.mod.funcs)-1]
				f.body = append([]*stmt{synthCall(p.lowering, def, "csrfUnprotected")}, f.body...)
			}
		case "class_definition":
			p.classDef(def)
		}
	case "class_definition":
		p.classDef(n)
	case "import_statement":
		p.importStmt(n)
	case "import_from_statement":
		p.importFrom(n)
	case "expression_statement":
		var out []*stmt
		for _, c := range p.named(n) {
			out = append(out, p.stmt(c)...)
		}
		return out
	case "pass_statement", "global_statement", "nonlocal_statement", "delete_statement", "assert_statement", "print_statement", "type_alias_statement":
	case "match_statement":
		s := &stmt{kind: stmtBranch, pos: p.pos(n), cond: p.expr(p.field(n, "subject"))}
		for _, c := range p.named(p.field(n, "body")) {
			s.arms = append(s.arms, p.block(p.field(c, "consequence")))
			var labels []*expr
			for _, pat := range p.named(c) {
				if p.kind(pat) != "block" {
					labels = append(labels, p.matchLabels(pat)...)
				}
			}
			s.labels = append(s.labels, labels)
		}
		return []*stmt{s}
	default:
		if e := p.expr(n); e != nil && p.isExprKind(k) {
			return []*stmt{{kind: stmtExpr, pos: p.pos(n), rhs: e}}
		}
	}
	return nil
}

func (p *pyLower) matchLabels(n *node) []*expr {
	if p.text(n) == "_" {
		return nil
	}
	switch p.kind(n) {
	case "string", "integer", "true", "false", "none":
		return []*expr{p.expr(n)}
	case "case_pattern", "union_pattern":
		var labels []*expr
		for _, c := range p.named(n) {
			labels = append(labels, p.matchLabels(c)...)
		}
		if len(labels) > 0 {
			return labels
		}
	}
	return []*expr{p.mk(exprOther, n)}
}

func (p *pyLower) isExprKind(k string) bool {
	switch k {
	case "call", "await", "yield", "attribute", "identifier", "binary_operator", "string", "concatenated_string",
		"list_comprehension", "generator_expression", "conditional_expression", "parenthesized_expression", "subscript":
		return true
	}
	return false
}

func (p *pyLower) firstOfKind(n *node, kind string) *node {
	for _, c := range p.named(n) {
		if p.kind(c) == kind {
			return c
		}
	}
	return nil
}

func (p *pyLower) ifStmt(n *node) *stmt {
	s := &stmt{kind: stmtIf, pos: p.pos(n), cond: p.expr(p.field(n, "condition")), then: p.block(p.field(n, "consequence"))}
	var els []*stmt
	for _, c := range p.named(n) {
		switch p.kind(c) {
		case "elif_clause":
			els = []*stmt{p.ifStmt(c)}
			// Later alternatives hang off the elif's own else branch.
			s.els = append(s.els, els...)
		case "else_clause":
			if b := p.field(c, "body"); b != nil {
				s.els = append(s.els, p.block(b)...)
			} else {
				for _, cc := range p.named(c) {
					s.els = append(s.els, p.block(cc)...)
				}
			}
		}
	}
	return s
}

func (p *pyLower) typeText(t *node) string {
	s := strings.TrimSpace(p.text(t))
	if i := strings.IndexAny(s, "[|("); i > 0 {
		s = s[:i]
	}
	return s
}

// targets flattens an assignment target, including tuple unpacking.
func (p *pyLower) targets(n *node) []*expr {
	if n == nil {
		return nil
	}
	switch p.kind(n) {
	case "pattern_list", "tuple_pattern", "list_pattern", "expression_list", "tuple", "list":
		var out []*expr
		for _, c := range p.named(n) {
			out = append(out, p.targets(c)...)
		}
		return out
	case "list_splat_pattern", "as_pattern_target", "parenthesized_expression":
		if cs := p.named(n); len(cs) > 0 {
			return p.targets(cs[0])
		}
	}
	return []*expr{p.expr(n)}
}

func (p *pyLower) importStmt(n *node) {
	for _, c := range p.named(n) {
		switch p.kind(c) {
		case "dotted_name":
			name := p.text(c)
			top, _, _ := strings.Cut(name, ".")
			p.mod.imports[top] = top
			p.mod.locals[top] = localRef{spec: name}
		case "aliased_import":
			name := p.text(p.field(c, "name"))
			alias := p.text(p.field(c, "alias"))
			p.mod.imports[alias] = name
			p.mod.locals[alias] = localRef{spec: name}
		}
	}
}

func (p *pyLower) importFrom(n *node) {
	modNode := p.field(n, "module_name")
	spec := strings.ReplaceAll(strings.TrimSpace(p.text(modNode)), " ", "")
	bind := func(local, name string) {
		p.mod.locals[local] = localRef{spec: spec, name: name}
		if !strings.HasPrefix(spec, ".") {
			p.mod.imports[local] = spec + "." + name
		}
	}
	for _, c := range p.named(n) {
		if c == modNode {
			continue
		}
		switch p.kind(c) {
		case "dotted_name":
			bind(p.text(c), p.text(c))
		case "aliased_import":
			bind(p.text(p.field(c, "alias")), p.text(p.field(c, "name")))
		}
	}
}

// decorators reports whether the function is a web route, whose arguments come from the
// request.
func (p *pyLower) decorators(def *node) bool {
	for _, c := range p.named(def) {
		if p.kind(c) != "decorator" {
			continue
		}
		t := p.text(c)
		for _, m := range []string{".route(", ".get(", ".post(", ".put(", ".delete(", ".patch(", ".api_route(", ".websocket("} {
			if strings.Contains(t, m) {
				return true
			}
		}
	}
	return false
}

// csrfExempt reports a view decorated to skip CSRF protection (@csrf_exempt, @csrf.exempt).
func (p *pyLower) csrfExempt(def *node) bool {
	for _, c := range p.named(def) {
		if p.kind(c) == "decorator" {
			t := p.text(c)
			if strings.Contains(t, "csrf_exempt") || strings.Contains(t, "csrf.exempt") {
				return true
			}
		}
	}
	return false
}

// htmlRoute reports a Flask-style route, whose string result is served as HTML.
func (p *pyLower) htmlRoute(def *node) bool {
	for _, c := range p.named(def) {
		if p.kind(c) == "decorator" && strings.Contains(p.text(c), ".route(") {
			return true
		}
	}
	return false
}

func (p *pyLower) function(n *node, isRoute bool, html ...bool) {
	f := &funcIR{name: p.text(p.field(n, "name")), class: p.class, pos: p.pos(n), htmlRoute: len(html) > 0 && html[0]}
	if f.name == "__init__" {
		f.name = "<init>"
	}
	if ps := p.field(n, "parameters"); ps != nil {
		for i, c := range p.named(ps) {
			pr := p.paramOf(c)
			if pr.name == "" {
				continue
			}
			if f.class != "" && i == 0 && (pr.name == "self" || pr.name == "cls") {
				continue
			}
			if isRoute && !routeInjected(pr.name, p.text(c)) && !isNumericType(pr.ty) {
				pr.source = "route parameter"
			}
			f.params = append(f.params, pr)
		}
	}
	f.body = p.block(p.field(n, "body"))
	p.mod.funcs = append(p.mod.funcs, f)
}

// routeInjected reports route handler parameters supplied by the framework rather than
// the client: the request object, a DB session, anything with a Depends() default.
func routeInjected(name, text string) bool {
	switch name {
	case "request", "req", "response", "db", "session", "background_tasks", "self", "cls":
		return true
	}
	return strings.Contains(text, "Depends(")
}

func (p *pyLower) paramOf(c *node) param {
	switch p.kind(c) {
	case "identifier":
		return param{name: p.text(c)}
	case "default_parameter":
		return param{name: p.text(p.field(c, "name"))}
	case "typed_parameter":
		pr := param{}
		for _, cc := range p.named(c) {
			if p.kind(cc) == "identifier" {
				pr.name = p.text(cc)
				break
			}
		}
		if t := p.field(c, "type"); t != nil {
			pr.ty = p.typeText(t)
		}
		return pr
	case "typed_default_parameter":
		pr := param{name: p.text(p.field(c, "name"))}
		if t := p.field(c, "type"); t != nil {
			pr.ty = p.typeText(t)
		}
		return pr
	case "list_splat_pattern", "dictionary_splat_pattern":
		if cs := p.named(c); len(cs) > 0 {
			return param{name: p.text(cs[0])}
		}
	}
	return param{}
}

func (p *pyLower) classDef(n *node) {
	prev := p.class
	p.class = p.text(p.field(n, "name"))
	defer func() { p.class = prev }()
	body := p.field(n, "body")
	for _, m := range p.named(body) {
		switch p.kind(m) {
		case "function_definition":
			p.function(m, false)
		case "decorated_definition":
			if def := p.field(m, "definition"); def != nil && p.kind(def) == "function_definition" {
				p.function(def, p.decorators(m), p.htmlRoute(m))
			}
		}
	}
}

func (p *pyLower) opBetween(n *node) string {
	l, r := p.field(n, "left"), p.field(n, "right")
	if l == nil || r == nil {
		return ""
	}
	return strings.TrimSpace(string(p.src[l.EndByte():r.StartByte()]))
}

func (p *pyLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch k := p.kind(n); k {
	case "identifier":
		e := p.mk(exprName, n)
		e.name = p.text(n)
		return e
	case "attribute":
		e := p.mk(exprMember, n)
		e.x = p.expr(p.field(n, "object"))
		e.name = p.text(p.field(n, "attribute"))
		return e
	case "subscript":
		e := p.mk(exprIndex, n)
		e.x = p.expr(p.field(n, "value"))
		e.args = []*expr{p.expr(p.field(n, "subscript"))}
		if idx := p.field(n, "subscript"); idx != nil && p.kind(idx) == "string" {
			m := p.mk(exprMember, n)
			m.x, m.name = e.x, p.stringConst(idx)
			return m
		}
		return e
	case "call":
		return p.call(n)
	case "string":
		return p.str(n)
	case "concatenated_string":
		e := p.mk(exprConcat, n)
		for _, c := range p.named(n) {
			e.args = append(e.args, p.expr(c))
		}
		return e
	case "integer", "float", "true", "false", "none", "ellipsis":
		e := p.mk(exprNum, n)
		e.str = p.text(n)
		return e
	case "binary_operator":
		l, r := p.expr(p.field(n, "left")), p.expr(p.field(n, "right"))
		op := p.opBetween(n)
		switch op {
		case "+", "%":
			e := p.mk(exprConcat, n)
			e.str = op
			e.args = []*expr{l, r}
			return e
		}
		// Python operators can build strings or paths. Preserve taint unless the
		// operands are known constants, rather than treating '*' or '/' as sanitizers.
		e := p.other(n, l, r)
		e.str = op
		return e
	case "unary_operator":
		op := p.text(p.field(n, "operator"))
		e := p.other(n, &expr{kind: exprNum, str: "0"}, p.expr(p.field(n, "argument")))
		e.str = op
		return e
	case "conditional_expression":
		if cs := p.named(n); len(cs) == 3 {
			return p.cond(n, p.expr(cs[1]), p.expr(cs[0]), p.expr(cs[2]))
		}
	case "boolean_operator":
		kind := exprAnd
		if p.opBetween(n) == "or" {
			kind = exprOr
		}
		e := p.mk(kind, n)
		e.args = []*expr{p.expr(p.field(n, "left")), p.expr(p.field(n, "right"))}
		return e
	case "not_operator":
		e := p.mk(exprNot, n)
		e.x = p.expr(p.field(n, "argument"))
		return e
	case "comparison_operator":
		cs := p.named(n)
		var result *expr
		for i := 1; i < len(cs); i++ {
			left, right := p.expr(cs[i-1]), p.expr(cs[i])
			between := strings.Join(strings.Fields(string(p.src[cs[i-1].EndByte():cs[i].StartByte()])), " ")
			var comparison *expr
			switch between {
			case "in", "not in":
				in := p.mk(exprIn, n)
				in.x, in.args = right, []*expr{left}
				comparison = in
				if between == "not in" {
					comparison = p.mk(exprNot, n)
					comparison.x = in
				}
			default:
				comparison = p.bin(n, between, left, right)
			}
			if result == nil {
				result = comparison
			} else {
				both := p.mk(exprAnd, n)
				both.args = []*expr{result, comparison}
				result = both
			}
		}
		return result
	case "lambda":
		e := p.mk(exprLambda, n)
		f := &funcIR{pos: p.pos(n)}
		if ps := p.field(n, "parameters"); ps != nil {
			for _, c := range p.named(ps) {
				f.params = append(f.params, p.paramOf(c))
			}
		}
		f.body = []*stmt{{kind: stmtReturn, pos: p.pos(n), rhs: p.expr(p.field(n, "body"))}}
		e.fn = f
		return e
	case "parenthesized_expression", "await", "yield", "list_splat", "dictionary_splat", "keyword_argument":
		cs := p.named(n)
		if k == "keyword_argument" {
			return p.expr(p.field(n, "value"))
		}
		if len(cs) > 0 {
			return p.expr(cs[len(cs)-1])
		}
	case "dictionary":
		// {"role": "system", "content": x}: request data in an LLM's instructions.
		var role, content *node
		d := p.mk(exprObject, n)
		for _, c := range p.named(n) {
			if p.kind(c) != "pair" {
				d.args = append(d.args, p.expr(c))
				continue
			}
			v := p.expr(p.field(c, "value"))
			if key := p.expr(p.field(c, "key")); key != nil && (key.kind == exprStr || key.kind == exprNum) {
				v = &expr{kind: exprField, pos: p.pos(c), name: key.str, x: v}
			}
			d.args = append(d.args, v)
			switch strings.Trim(p.text(p.field(c, "key")), `"'`) {
			case "role":
				role = p.field(c, "value")
			case "content":
				content = p.field(c, "value")
			}
		}
		if role != nil && content != nil && strings.Trim(p.text(role), `"'`) == "system" {
			call := p.mk(exprCall, n)
			fn := p.mk(exprName, n)
			fn.name = "llmPrompt"
			call.x = fn
			call.args = []*expr{p.expr(content)}
			call.kw = []string{""}
			d.args = append(d.args, call)
		}
		return d
	case "list":
		e := p.mk(exprSequence, n)
		for _, c := range p.named(n) {
			if p.kind(c) == "list_splat" {
				e.kind = exprOther
			}
			e.args = append(e.args, p.expr(c))
		}
		return e
	case "named_expression":
		return p.expr(p.field(n, "value"))
	}
	e := p.mk(exprOther, n)
	for _, c := range p.named(n) {
		if x := p.expr(c); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

// stringConst is the value of a string literal without interpolation.
func (p *pyLower) stringConst(n *node) string {
	var b strings.Builder
	for _, c := range p.named(n) {
		if p.kind(c) == "string_content" {
			b.WriteString(p.text(c))
		}
	}
	return b.String()
}

// str lowers a string literal; an f-string with interpolations is string building.
func (p *pyLower) str(n *node) *expr {
	text := p.text(n)
	quote := strings.IndexAny(text, "\"'")
	prefix := ""
	if quote >= 0 {
		prefix = strings.ToLower(text[:quote])
	}
	raw := strings.Contains(prefix, "r")
	var subs []*expr
	interpolated := false
	for _, c := range p.named(n) {
		switch p.kind(c) {
		case "string_content":
			part := p.mk(exprStr, c)
			value, ok := pythonText(p.text(c), raw)
			part.str = strings.ReplaceAll(strings.ReplaceAll(value, "{{", "{"), "}}", "}")
			part.unknownText = !ok
			subs = append(subs, part)
		case "interpolation":
			interpolated = true
			if x := p.expr(p.field(c, "expression")); x != nil {
				for _, child := range p.named(c) {
					if p.kind(child) == "type_conversion" || p.kind(child) == "format_specifier" {
						x = p.other(c, x)
						break
					}
				}
				subs = append(subs, x)
			}
		}
	}
	if !interpolated {
		e := p.mk(exprStr, n)
		e.str = p.stringConst(n)
		e.unknownText = true
		if quote >= 0 && !strings.ContainsAny(prefix, "bf") {
			delimiter := 1
			if strings.HasPrefix(text[quote:], strings.Repeat(text[quote:quote+1], 3)) {
				delimiter = 3
			}
			if len(text) >= quote+2*delimiter {
				if value, ok := pythonText(text[quote+delimiter:len(text)-delimiter], raw); ok {
					e.str, e.unknownText = value, false
				}
			}
		}
		return e
	}
	e := p.mk(exprConcat, n)
	e.unknownText = true
	e.str = "interpolate"
	e.args = subs
	return e
}

func (p *pyLower) call(n *node) *expr {
	fn := p.field(n, "function")
	e := p.mk(exprCall, n)
	e.x = p.expr(fn)
	if e.x == nil {
		e.x = p.mk(exprOther, n)
	}
	for _, a := range p.named(p.field(n, "arguments")) {
		name := ""
		if p.kind(a) == "keyword_argument" {
			name = p.text(p.field(a, "name"))
		}
		e.args = append(e.args, p.expr(a))
		e.kw = append(e.kw, name)
	}
	if q := p.text(fn); (q == "re.match" || q == "re.fullmatch" || q == "re.search") && len(e.args) >= 2 && e.args[0].kind == exprStr {
		if raw := p.firstArgText(n); raw != "" && strictLiteral(e.args[0].str, "", false) {
			return guardOf(p.pos(n), e.args[1])
		}
	}
	if e.x.kind == exprMember && e.x.name == "startswith" && len(e.args) == 1 {
		in := p.mk(exprIn, n)
		in.x, in.args = e.args[0], []*expr{e.x.x}
		in.str = "prefix"
		if as := p.named(p.field(n, "arguments")); len(as) == 1 {
			return withWeakAllow(in, p.weakAllow(p.pos(n), p.text(p.field(fn, "object")), p.text(as[0])))
		}
		return in
	}
	if e.x.kind == exprMember {
		// "...{}".format(x) and "sep".join(xs) build strings out of their arguments.
		switch e.x.name {
		case "format", "join", "format_map":
			c := p.mk(exprConcat, n)
			c.unknownText = true
			c.args = append([]*expr{e.x.x}, e.args...)
			return c
		case "append", "extend", "add", "insert", "update", "write":
			// handled by the generic receiver/argument union
		}
	}
	return e
}

func (p *pyLower) firstArgText(call *node) string {
	if cs := p.named(p.field(call, "arguments")); len(cs) > 0 {
		return p.text(cs[0])
	}
	return ""
}
