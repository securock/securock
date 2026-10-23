package sast

import (
	"strings"

	"github.com/odvcencio/gotreesitter"
)

type node = gotreesitter.Node

// jsPairChecks are object keys whose value is checked by a misuse entry of the same
// name: { rejectUnauthorized: false }, { nodeIntegration: true }.
var jsPairChecks = map[string]bool{
	"rejectUnauthorized": true, "algorithms": true, "nodeIntegration": true, "contextIsolation": true,
	"webSecurity": true, "allowRunningInsecureContent": true, "secretOrKey": true,
}

var jsRequestRoot = map[string]string{
	"query": "request query", "body": "request body", "params": "request path parameter",
	"headers": "request header", "cookies": "request cookie", "signedCookies": "request cookie",
	"url": "request URL", "originalUrl": "request URL", "path": "request path",
	"hostname": "request host", "host": "request host", "baseUrl": "request URL",
	"files": "uploaded file", "file": "uploaded file", "rawBody": "request body",
	"get": "request header", "header": "request header", "param": "request parameter",
	"json": "request body", "text": "request body", "formData": "request body",
	"searchParams": "request query", "nextUrl": "request URL",
}

var jsSpec = &langSpec{
	name: "js",
	sinks: map[string]sink{
		"child_process.exec":         {kind: kCmd, args: []int{0}},
		"child_process.execSync":     {kind: kCmd, args: []int{0}},
		"child_process.spawn":        {kind: kCmd, args: []int{0}},
		"child_process.spawnSync":    {kind: kCmd, args: []int{0}},
		"child_process.execFile":     {kind: kCmd, args: []int{0}},
		"child_process.execFileSync": {kind: kCmd, args: []int{0}},
		"shelljs.exec":               {kind: kCmd, args: []int{0}},
		"execa":                      {kind: kCmd, args: []int{0}},
		"execa.command":              {kind: kCmd, args: []int{0}},

		"fs.readFile": {kind: kPath, args: []int{0}}, "fs.readFileSync": {kind: kPath, args: []int{0}},
		"fs.writeFile": {kind: kPath, args: []int{0}}, "fs.writeFileSync": {kind: kPath, args: []int{0}},
		"fs.appendFile": {kind: kPath, args: []int{0}}, "fs.appendFileSync": {kind: kPath, args: []int{0}},
		"fs.createReadStream": {kind: kPath, args: []int{0}}, "fs.createWriteStream": {kind: kPath, args: []int{0}},
		"fs.unlink": {kind: kPath, args: []int{0}}, "fs.unlinkSync": {kind: kPath, args: []int{0}},
		"fs.rm": {kind: kPath, args: []int{0}}, "fs.rmSync": {kind: kPath, args: []int{0}},
		"fs.readdir": {kind: kPath, args: []int{0}}, "fs.readdirSync": {kind: kPath, args: []int{0}},
		"fs.open": {kind: kPath, args: []int{0}}, "fs.openSync": {kind: kPath, args: []int{0}},
		"fs.rename": {kind: kPath, args: []int{0, 1}}, "fs.copyFile": {kind: kPath, args: []int{0, 1}},
		"fs.promises.readFile": {kind: kPath, args: []int{0}}, "fs.promises.writeFile": {kind: kPath, args: []int{0}},
		"fs.promises.unlink": {kind: kPath, args: []int{0}}, "fs.promises.rm": {kind: kPath, args: []int{0}},
		"fs/promises.readFile": {kind: kPath, args: []int{0}}, "fs/promises.writeFile": {kind: kPath, args: []int{0}},
		"fs/promises.unlink": {kind: kPath, args: []int{0}}, "fs/promises.rm": {kind: kPath, args: []int{0}},
		"?.sendFile": {kind: kPath, args: []int{0}, recv: []string{"res", "response", "reply"}},
		"?.download": {kind: kPath, args: []int{0}, recv: []string{"res", "response", "reply"}},

		"axios": {kind: kSSRF, args: []int{0}}, "axios.get": {kind: kSSRF, args: []int{0}},
		"axios.post": {kind: kSSRF, args: []int{0}}, "axios.put": {kind: kSSRF, args: []int{0}},
		"axios.delete": {kind: kSSRF, args: []int{0}}, "axios.request": {kind: kSSRF, args: []int{0}},
		"axios.head": {kind: kSSRF, args: []int{0}}, "axios.patch": {kind: kSSRF, args: []int{0}},
		"fetch": {kind: kSSRF, args: []int{0}}, "node-fetch": {kind: kSSRF, args: []int{0}},
		"got": {kind: kSSRF, args: []int{0}}, "got.get": {kind: kSSRF, args: []int{0}}, "got.post": {kind: kSSRF, args: []int{0}},
		"request": {kind: kSSRF, args: []int{0}}, "request.get": {kind: kSSRF, args: []int{0}},
		"needle.get": {kind: kSSRF, args: []int{0}},
		"http.get":   {kind: kSSRF, args: []int{0}}, "http.request": {kind: kSSRF, args: []int{0}},
		"https.get": {kind: kSSRF, args: []int{0}}, "https.request": {kind: kSSRF, args: []int{0}},

		"eval": {kind: kCode, args: []int{0}}, "Function": {kind: kCode, args: []int{0, 1, 2, 3}},
		"vm.runInThisContext": {kind: kCode, args: []int{0}}, "vm.runInNewContext": {kind: kCode, args: []int{0}},
		"vm.runInContext": {kind: kCode, args: []int{0}}, "vm.Script": {kind: kCode, args: []int{0}},
		"node-serialize.unserialize": {kind: kDeser, args: []int{0}},

		"dangerouslySetInnerHTML": {kind: kXSS, args: []int{0}},
		"document.write":          {kind: kXSS, args: []int{0}}, "document.writeln": {kind: kXSS, args: []int{0}},
		"?.insertAdjacentHTML": {kind: kXSS, args: []int{1}},
		"?.send":               {kind: kXSS, args: []int{0}, recv: []string{"res", "response", "reply"}},
		"?.write":              {kind: kXSS, args: []int{0}, recv: []string{"res", "response", "reply"}},
		"?.end":                {kind: kXSS, args: []int{0}, recv: []string{"res", "response", "reply"}},
		"?.redirect":           {kind: kRedirect, args: []int{0, 1}, recv: []string{"res", "response", "reply", "ctx"}},

		"?.query": {kind: kSQL, args: []int{0}}, "?.execute": {kind: kSQL, args: []int{0}},
		"?.raw": {kind: kSQL, args: []int{0}}, "?.whereRaw": {kind: kSQL, args: []int{0}},
		"?.orderByRaw": {kind: kSQL, args: []int{0}}, "?.havingRaw": {kind: kSQL, args: []int{0}},
		"?.groupByRaw": {kind: kSQL, args: []int{0}}, "?.selectRaw": {kind: kSQL, args: []int{0}},
		"?.$queryRawUnsafe": {kind: kSQL, args: []int{0}}, "?.$executeRawUnsafe": {kind: kSQL, args: []int{0}},
		"?.queryRawUnsafe": {kind: kSQL, args: []int{0}}, "?.executeRawUnsafe": {kind: kSQL, args: []int{0}},
		"?.run": {kind: kSQL, args: []int{0}, recv: dbNames}, "?.all": {kind: kSQL, args: []int{0}, recv: dbNames},
		"?.get": {kind: kSQL, args: []int{0}, recv: dbNames}, "?.exec": {kind: kSQL, args: []int{0}, recv: dbNames},
		"?.each": {kind: kSQL, args: []int{0}, recv: dbNames},
	},
	sanitizers: map[string]kind{
		"encodeURIComponent": kXSS | kPath | kRedirect | kSSRF, "encodeURI": kXSS | kPath | kRedirect | kSSRF,
		"path.basename": kPath, "escape-html": kXSS, "he.encode": kXSS, "he.escape": kXSS,
		"validator.escape": kXSS, "dompurify.sanitize": kXSS, "sanitize-html": kXSS, "xss": kXSS,
		"lodash.escape": kXSS, "mysql.escape": kSQL, "mysql2.escape": kSQL, "sqlstring.escape": kSQL,
		"?.escapeLiteral": kSQL, "?.escapeId": kSQL | kPath,
		"parseInt": kAll, "parseFloat": kAll, "Number": kAll, "Boolean": kAll,
		"Math.floor": kAll, "Math.round": kAll, "Math.max": kAll, "Math.min": kAll, "Math.abs": kAll,
		"uuid.validate": kAll, "crypto.createHash": kAll,
	},
	sourcePrefixes: map[string]string{
		"process.argv": "command-line arguments", "window.location": "browser URL", "document.location": "browser URL",
		"document.cookie": "browser cookie", "document.referrer": "browser referrer", "location": "browser URL",
		"window.name": "browser window name",
	},
	sourceRoots: map[string]map[string]string{
		"req": jsRequestRoot, "request": jsRequestRoot,
		"ctx":          {"query": "request query", "params": "request path parameter", "request": "request", "path": "request path", "querystring": "request query"},
		"event":        {"queryStringParameters": "request query", "body": "request body", "pathParameters": "request path parameter", "headers": "request header"},
		"searchParams": {"*": "request query"},
		"context":      {"query": "request query", "params": "request parameter", "req": "request"},
	},
	returns:     map[string]string{},
	mutators:    map[string]bool{"push": true, "unshift": true, "add": true, "set": true, "append": true},
	self:        map[string]bool{"this": true},
	shells:      map[string]bool{"sh": true, "bash": true, "zsh": true, "cmd": true, "cmd.exe": true, "/bin/sh": true, "/bin/bash": true, "powershell": true},
	assignSinks: map[string]kind{"innerHTML": kXSS, "outerHTML": kXSS},
	builtins: map[string]bool{
		"eval": true, "Function": true, "fetch": true, "encodeURIComponent": true, "encodeURI": true,
		"parseInt": true, "parseFloat": true, "Number": true, "Boolean": true, "window": true, "document": true,
		"location": true, "process": true, "Math": true, "dangerouslySetInnerHTML": true,
	},
}

var nestSources = map[string]string{
	"Query": "request query", "Param": "request path parameter", "Body": "request body",
	"Headers": "request header", "Cookies": "request cookie", "UploadedFile": "uploaded file", "UploadedFiles": "uploaded file",
}

var dbNames = []string{"db", "database", "conn", "connection", "client", "pool", "sqlite", "knex", "sequelize", "pg", "mysql", "dbh"}

func init() { frontends["js"] = &frontend{spec: jsSpec, lower: lowerJS} }

type jsLower struct {
	*lowering
	class string
}

func lowerJS(l *lowering) *module {
	j := &jsLower{lowering: l}
	l.mod.top = j.stmts(l.named(l.root))
	return l.mod
}

func (j *jsLower) stmts(ns []*node) []*stmt {
	var out []*stmt
	for _, n := range ns {
		out = append(out, j.stmt(n)...)
	}
	return out
}

func (j *jsLower) body(n *node) []*stmt {
	if n == nil {
		return nil
	}
	if j.kind(n) == "statement_block" {
		return j.stmts(j.named(n))
	}
	return j.stmt(n)
}

func (j *jsLower) stmt(n *node) []*stmt {
	switch k := j.kind(n); k {
	case "expression_statement":
		var out []*stmt
		for _, c := range j.named(n) {
			out = append(out, j.exprStmt(c))
		}
		return out
	case "lexical_declaration", "variable_declaration":
		var out []*stmt
		for _, d := range j.named(n) {
			if j.kind(d) == "variable_declarator" {
				out = append(out, j.declarator(d)...)
			}
		}
		return out
	case "return_statement":
		cs := j.named(n)
		s := &stmt{kind: stmtReturn, pos: j.pos(n)}
		if len(cs) > 0 {
			s.rhs = j.expr(cs[0])
		}
		return []*stmt{s}
	case "throw_statement":
		cs := j.named(n)
		s := &stmt{kind: stmtJump, pos: j.pos(n)}
		if len(cs) > 0 {
			s.rhs = j.expr(cs[0])
		}
		return []*stmt{s}
	case "break_statement", "continue_statement":
		return []*stmt{{kind: stmtJump, pos: j.pos(n), loop: true, next: k == "continue_statement"}}
	case "if_statement":
		s := &stmt{kind: stmtIf, pos: j.pos(n), cond: j.expr(j.field(n, "condition")), then: j.body(j.field(n, "consequence"))}
		if alt := j.field(n, "alternative"); alt != nil {
			for _, c := range j.named(alt) {
				s.els = append(s.els, j.body(c)...)
			}
		}
		return []*stmt{s}
	case "for_in_statement":
		s := &stmt{kind: stmtLoop, pos: j.pos(n), rhs: j.expr(j.field(n, "right")), then: j.body(j.field(n, "body"))}
		s.lhs = j.targets(j.field(n, "left"))
		return []*stmt{s}
	case "for_statement":
		var out []*stmt
		if init := j.field(n, "initializer"); init != nil {
			out = append(out, j.stmt(init)...)
		}
		body := j.body(j.field(n, "body"))
		out = append(out, &stmt{kind: stmtLoop, pos: j.pos(n), then: body, cond: j.expr(j.field(n, "condition"))})
		return out
	case "while_statement", "do_statement":
		return []*stmt{{kind: stmtLoop, pos: j.pos(n), then: j.body(j.field(n, "body")), cond: j.expr(j.field(n, "condition"))}}
	case "statement_block":
		return []*stmt{{kind: stmtBranch, pos: j.pos(n), arms: [][]*stmt{j.stmts(j.named(n))}}}
	case "switch_statement":
		s := &stmt{kind: stmtBranch, pos: j.pos(n)}
		if b := j.field(n, "body"); b != nil {
			for _, c := range j.named(b) {
				var arm []*stmt
				for _, cc := range j.named(c) {
					if cc != j.field(c, "value") {
						arm = append(arm, j.stmt(cc)...)
					}
				}
				s.arms = append(s.arms, arm)
			}
		}
		return []*stmt{s}
	case "try_statement":
		s := &stmt{kind: stmtBranch, pos: j.pos(n)}
		s.arms = append(s.arms, j.body(j.field(n, "body")))
		if h := j.field(n, "handler"); h != nil {
			s.arms = append(s.arms, j.body(j.field(h, "body")))
		}
		if f := j.field(n, "finalizer"); f != nil {
			s.arms = append(s.arms, j.body(j.field(f, "body")))
		}
		return []*stmt{s}
	case "labeled_statement":
		cs := j.named(n)
		if len(cs) > 1 {
			return j.stmt(cs[len(cs)-1])
		}
	case "function_declaration", "generator_function_declaration":
		name := j.text(j.field(n, "name"))
		j.mod.funcs = append(j.mod.funcs, j.function(n, name))
		j.constructorMethods(name, j.field(n, "body"))
	case "class_declaration":
		j.classDecl(n)
	case "export_statement":
		var out []*stmt
		for _, c := range j.named(n) {
			out = append(out, j.stmt(c)...)
		}
		return out
	case "import_statement":
		j.importStmt(n)
	}
	return nil
}

// isFunc reports whether a node is a function expression.
func (j *jsLower) isFunc(n *node) bool {
	switch j.kind(n) {
	case "arrow_function", "function_expression", "function", "generator_function":
		return true
	}
	return false
}

// constructorMethods registers the methods of the older class idiom: a function whose
// body assigns this.name = function/arrow, as in
//
//	function AllocationsDAO(db) { this.getByUser = (id, cb) => {...} }
func (j *jsLower) constructorMethods(class string, body *node) {
	if body == nil || class == "" || class[0] < 'A' || class[0] > 'Z' {
		return
	}
	prev := j.class
	j.class = class
	defer func() { j.class = prev }()
	for _, st := range j.named(body) {
		if j.kind(st) != "expression_statement" {
			continue
		}
		for _, a := range j.named(st) {
			if j.kind(a) != "assignment_expression" {
				continue
			}
			left, right := j.field(a, "left"), j.field(a, "right")
			if left == nil || right == nil || j.kind(left) != "member_expression" || !j.isFunc(right) {
				continue
			}
			if obj := j.field(left, "object"); obj != nil && j.kind(obj) == "this" {
				j.mod.funcs = append(j.mod.funcs, j.function(right, j.text(j.field(left, "property"))))
			}
		}
	}
}

// prototypeMethod handles X.prototype.name = function() {...}.
func (j *jsLower) prototypeMethod(a *node) {
	left, right := j.field(a, "left"), j.field(a, "right")
	if left == nil || right == nil || j.kind(left) != "member_expression" || !j.isFunc(right) {
		return
	}
	obj := j.field(left, "object")
	if obj == nil || j.kind(obj) != "member_expression" || j.text(j.field(obj, "property")) != "prototype" {
		return
	}
	class := j.text(j.field(obj, "object"))
	prev := j.class
	j.class = class
	j.mod.funcs = append(j.mod.funcs, j.function(right, j.text(j.field(left, "property"))))
	j.class = prev
}

func (j *jsLower) exprStmt(n *node) *stmt {
	if k := j.kind(n); k == "assignment_expression" || k == "augmented_assignment_expression" {
		j.prototypeMethod(n)
		return j.assignment(n)
	}
	return &stmt{kind: stmtExpr, pos: j.pos(n), rhs: j.expr(n)}
}

func (j *jsLower) assignment(n *node) *stmt {
	s := &stmt{kind: stmtAssign, pos: j.pos(n), rhs: j.expr(j.field(n, "right")), aug: j.kind(n) == "augmented_assignment_expression"}
	s.lhs = j.targets(j.field(n, "left"))
	return s
}

// targets flattens an assignment target, including destructuring, into variables.
func (j *jsLower) targets(n *node) []*expr {
	if n == nil {
		return nil
	}
	switch j.kind(n) {
	case "object_pattern", "array_pattern":
		var out []*expr
		for _, c := range j.named(n) {
			out = append(out, j.targets(c)...)
		}
		return out
	case "shorthand_property_identifier_pattern", "identifier", "shorthand_property_identifier":
		e := j.mk(exprName, n)
		e.name = j.text(n)
		return []*expr{e}
	case "pair_pattern":
		return j.targets(j.field(n, "value"))
	case "rest_pattern", "assignment_pattern", "object_assignment_pattern":
		cs := j.named(n)
		if len(cs) > 0 {
			return j.targets(cs[0])
		}
	case "parenthesized_expression":
		return j.targets(j.named(n)[0])
	}
	return []*expr{j.expr(n)}
}

func (j *jsLower) declarator(d *node) []*stmt {
	name := j.field(d, "name")
	value := j.field(d, "value")
	ty := ""
	if t := j.field(d, "type"); t != nil {
		ty = j.typeText(t)
	}
	// const cp = require("child_process") and const {exec} = require(...)
	if value != nil && j.kind(value) == "call_expression" {
		if fn := j.field(value, "function"); fn != nil && j.text(fn) == "require" {
			if spec := j.firstString(j.field(value, "arguments")); spec != "" {
				j.requireBinding(name, spec)
				return nil
			}
		}
	}
	if value == nil {
		return nil
	}
	s := &stmt{kind: stmtAssign, pos: j.pos(d), rhs: j.expr(value), lhs: j.targets(name)}
	if ty != "" && len(s.lhs) == 1 {
		s.lhs[0].ty = ty
	}
	// const handler = (req) => {...} defines a function other code calls by name.
	if j.isFunc(value) && j.kind(name) == "identifier" {
		fname := j.text(name)
		j.mod.funcs = append(j.mod.funcs, j.function(value, fname))
		j.constructorMethods(fname, j.field(value, "body"))
	}
	return []*stmt{s}
}

func (j *jsLower) typeText(t *node) string {
	s := strings.TrimSpace(strings.TrimPrefix(j.text(t), ":"))
	if i := strings.IndexAny(s, "<[| "); i > 0 {
		s = s[:i]
	}
	return s
}

func (j *jsLower) firstString(args *node) string {
	for _, c := range j.named(args) {
		if j.kind(c) == "string" {
			return j.stringValue(c)
		}
	}
	return ""
}

func (j *jsLower) stringValue(n *node) string {
	var b strings.Builder
	for _, c := range j.named(n) {
		if k := j.kind(c); k == "string_fragment" || k == "escape_sequence" {
			b.WriteString(j.text(c))
		}
	}
	return b.String()
}

func normalizeModule(spec string) string { return strings.TrimPrefix(spec, "node:") }

func (j *jsLower) bindModule(local, spec, member string) {
	spec = normalizeModule(spec)
	if strings.HasPrefix(spec, ".") {
		j.mod.locals[local] = localRef{spec: spec, name: member}
		return
	}
	q := spec
	if member != "" {
		q = spec + "." + member
	}
	j.mod.imports[local] = q
}

func (j *jsLower) requireBinding(name *node, spec string) {
	switch j.kind(name) {
	case "identifier":
		j.bindModule(j.text(name), spec, "")
	case "object_pattern":
		for _, c := range j.named(name) {
			switch j.kind(c) {
			case "shorthand_property_identifier_pattern":
				j.bindModule(j.text(c), spec, j.text(c))
			case "pair_pattern":
				if v := j.field(c, "value"); v != nil && j.kind(v) == "identifier" {
					j.bindModule(j.text(v), spec, j.text(j.field(c, "key")))
				}
			}
		}
	}
}

func (j *jsLower) importStmt(n *node) {
	src := j.field(n, "source")
	if src == nil {
		return
	}
	spec := j.stringValue(src)
	for _, c := range j.named(n) {
		if j.kind(c) != "import_clause" {
			continue
		}
		for _, cc := range j.named(c) {
			switch j.kind(cc) {
			case "identifier":
				j.bindModule(j.text(cc), spec, "")
			case "namespace_import":
				for _, id := range j.named(cc) {
					j.bindModule(j.text(id), spec, "")
				}
			case "named_imports":
				for _, is := range j.named(cc) {
					name := j.text(j.field(is, "name"))
					local := name
					if a := j.field(is, "alias"); a != nil {
						local = j.text(a)
					}
					j.bindModule(local, spec, name)
				}
			}
		}
	}
}

func (j *jsLower) params(n *node) []param {
	var out []param
	for _, p := range j.named(n) {
		out = append(out, j.paramOf(p))
	}
	return out
}

func (j *jsLower) paramOf(p *node) param {
	switch j.kind(p) {
	case "identifier":
		return param{name: j.text(p)}
	case "required_parameter", "optional_parameter":
		pat := j.field(p, "pattern")
		pr := param{name: "\x00destructured"}
		// NestJS: @Query('x') name, @Param(), @Body(), @Headers() fill the argument from the request.
		for _, c := range j.named(p) {
			if j.kind(c) == "decorator" {
				name := strings.TrimPrefix(strings.SplitN(j.text(c), "(", 2)[0], "@")
				if desc, ok := nestSources[name]; ok {
					pr.source = desc
				}
			}
		}
		if pat != nil && j.kind(pat) == "identifier" {
			pr.name = j.text(pat)
		}
		if t := j.field(p, "type"); t != nil {
			pr.ty = j.typeText(t)
		}
		return pr
	case "assignment_pattern":
		return j.paramOf(j.field(p, "left"))
	case "rest_pattern":
		if cs := j.named(p); len(cs) > 0 {
			return j.paramOf(cs[0])
		}
	}
	return param{name: "\x00destructured"}
}

func (j *jsLower) function(n *node, name string) *funcIR {
	f := &funcIR{name: name, class: j.class, pos: j.pos(n)}
	if p := j.field(n, "parameters"); p != nil {
		f.params = j.params(p)
	} else if p := j.field(n, "parameter"); p != nil {
		f.params = []param{{name: j.text(p)}}
	}
	f.body = j.body(j.field(n, "body"))
	if b := j.field(n, "body"); b != nil && j.kind(b) != "statement_block" {
		f.body = []*stmt{{kind: stmtReturn, pos: j.pos(b), rhs: j.expr(b)}}
	}
	f.body = append(j.requestDestructuring(j.field(n, "parameters")), f.body...)
	return f
}

var requestMembers = map[string]bool{"query": true, "body": true, "params": true, "headers": true, "cookies": true}

// requestDestructuring handles an Express handler written ({ query, body }, res) => ...:
// each destructured name is read from the request object, so it is request data.
func (j *jsLower) llmPrompt(at *node, value *node) *expr {
	call := j.mk(exprCall, at)
	fn := j.mk(exprName, at)
	fn.name = "llmPrompt"
	call.x = fn
	call.args = []*expr{j.expr(value)}
	call.kw = []string{""}
	return call
}

func (j *jsLower) requestDestructuring(params *node) []*stmt {
	if params == nil {
		return nil
	}
	ps := j.named(params)
	if len(ps) == 0 {
		return nil
	}
	var pat *node
	handler := false
	switch j.kind(ps[0]) {
	case "object_pattern":
		pat = ps[0]
	case "required_parameter":
		pat = j.field(ps[0], "pattern")
		if t := j.field(ps[0], "type"); t != nil && strings.Contains(j.text(t), "Request") {
			handler = true
		}
	}
	if pat == nil || j.kind(pat) != "object_pattern" {
		return nil
	}
	for _, p := range ps[1:] {
		name := j.text(p)
		if pt := j.field(p, "pattern"); pt != nil {
			name = j.text(pt)
		}
		switch strings.TrimPrefix(strings.TrimSpace(name), "_") {
		case "res", "response", "reply", "next":
			handler = true
		}
	}
	if !handler {
		return nil
	}
	var out []*stmt
	for _, c := range j.named(pat) {
		prop, local := "", ""
		switch j.kind(c) {
		case "shorthand_property_identifier_pattern":
			prop = j.text(c)
			local = prop
		case "pair_pattern":
			prop = strings.Trim(j.text(j.field(c, "key")), `"'`)
			local = j.text(j.field(c, "value"))
		}
		if !requestMembers[prop] || local == "" {
			continue
		}
		req := j.mk(exprName, c)
		req.name = "req"
		src := j.mk(exprMember, c)
		src.x, src.name = req, prop
		name := j.mk(exprName, c)
		name.name = local
		out = append(out, &stmt{kind: stmtAssign, pos: j.pos(c), lhs: []*expr{name}, rhs: src, binds: true})
	}
	return out
}

func (j *jsLower) classDecl(n *node) {
	name := j.text(j.field(n, "name"))
	prev := j.class
	j.class = name
	defer func() { j.class = prev }()
	body := j.field(n, "body")
	for _, m := range j.named(body) {
		switch j.kind(m) {
		case "public_field_definition", "field_definition":
			j.field_(name, m)
			continue
		case "method_definition":
		default:
			continue
		}
		mn := j.text(j.field(m, "name"))
		if mn == "constructor" {
			mn = "<init>"
		}
		f := j.function(m, mn)
		j.mod.funcs = append(j.mod.funcs, f)
	}
}

// field_ records the type of a class field, from its annotation or its initializer.
func (j *jsLower) field_(class string, m *node) {
	fname := j.text(j.field(m, "name"))
	ty := ""
	if t := j.field(m, "type"); t != nil {
		ty = j.typeText(t)
	}
	if v := j.field(m, "value"); ty == "" && v != nil && j.kind(v) == "new_expression" {
		ty = j.text(j.field(v, "constructor"))
	}
	if ty == "" {
		return
	}
	if j.mod.fields[class] == nil {
		j.mod.fields[class] = map[string]string{}
	}
	if q, ok := j.mod.imports[ty]; ok {
		ty = q
	}
	j.mod.fields[class][fname] = ty
}

func (j *jsLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch k := j.kind(n); k {
	case "identifier", "shorthand_property_identifier", "this", "super":
		e := j.mk(exprName, n)
		e.name = j.text(n)
		return e
	case "member_expression":
		e := j.mk(exprMember, n)
		e.x = j.expr(j.field(n, "object"))
		e.name = j.text(j.field(n, "property"))
		return e
	case "subscript_expression":
		e := j.mk(exprIndex, n)
		e.x = j.expr(j.field(n, "object"))
		e.args = []*expr{j.expr(j.field(n, "index"))}
		// A constant key reads like a member: req.query["id"].
		if idx := j.field(n, "index"); idx != nil && j.kind(idx) == "string" {
			m := j.mk(exprMember, n)
			m.x, m.name = e.x, j.stringValue(idx)
			return m
		}
		return e
	case "call_expression":
		return j.call(n, exprCall, j.field(n, "function"))
	case "new_expression":
		return j.call(n, exprNew, j.field(n, "constructor"))
	case "string":
		e := j.mk(exprStr, n)
		e.str = j.stringValue(n)
		return e
	case "template_string":
		e := j.mk(exprConcat, n)
		hasSub := false
		for _, c := range j.named(n) {
			if j.kind(c) == "template_substitution" {
				hasSub = true
				for _, s := range j.named(c) {
					e.args = append(e.args, j.expr(s))
				}
			}
		}
		if !hasSub {
			s := j.mk(exprStr, n)
			s.str = strings.Trim(j.text(n), "`")
			return s
		}
		return e
	case "number", "true", "false", "null", "undefined", "regex":
		e := j.mk(exprNum, n)
		e.str = j.text(n)
		return e
	case "binary_expression":
		l, r := j.expr(j.field(n, "left")), j.expr(j.field(n, "right"))
		switch j.text(j.field(n, "operator")) {
		case "+":
			e := j.mk(exprConcat, n)
			e.args = []*expr{l, r}
			return e
		case "&&":
			e := j.mk(exprAnd, n)
			e.args = []*expr{l, r}
			return e
		case "||", "??":
			e := j.mk(exprOr, n)
			e.args = []*expr{l, r}
			return e
		case "in":
			e := j.mk(exprIn, n)
			e.x, e.args = r, []*expr{l}
			return e
		case "==", "===", "!=", "!==", "<", ">", "<=", ">=":
			return j.bin(n, j.text(j.field(n, "operator")), l, r)
		case "-", "*", "/", "%":
			return j.bin(n, j.text(j.field(n, "operator")), l, r)
		case "instanceof":
			return j.mk(exprNum, n)
		}
		return j.other(n, l, r)
	case "unary_expression":
		op := j.text(j.field(n, "operator"))
		arg := j.expr(j.field(n, "argument"))
		if op == "!" {
			e := j.mk(exprNot, n)
			e.x = arg
			return e
		}
		if op == "typeof" || op == "void" {
			return j.mk(exprNum, n)
		}
		return j.other(n, arg)
	case "arrow_function", "function_expression", "function", "generator_function":
		e := j.mk(exprLambda, n)
		e.fn = j.function(n, "")
		return e
	case "parenthesized_expression", "await_expression", "as_expression", "non_null_expression", "satisfies_expression", "type_assertion", "spread_element":
		if cs := j.named(n); len(cs) > 0 {
			return j.expr(cs[0])
		}
	case "ternary_expression":
		return j.cond(n, j.expr(j.field(n, "condition")), j.expr(j.field(n, "consequence")), j.expr(j.field(n, "alternative")))
	case "object":
		// { origin: true, credentials: true } hands credentials to any website.
		e := j.mk(exprObject, n)
		var origin, creds, secret, keys *node
		sessionOpts := false
		for _, c := range j.named(n) {
			if x := j.expr(c); x != nil {
				if j.kind(c) == "pair" && j.kind(j.field(c, "key")) != "computed_property_name" {
					x = &expr{kind: exprField, pos: j.pos(c), name: strings.Trim(j.text(j.field(c, "key")), `"'`), x: x}
				} else if j.kind(c) == "shorthand_property_identifier" {
					x = &expr{kind: exprField, pos: j.pos(c), name: j.text(c), x: x}
				}
				e.args = append(e.args, x)
			}
			if j.kind(c) == "pair" {
				switch strings.Trim(j.text(j.field(c, "key")), `"'`) {
				case "secret":
					secret = j.field(c, "value")
				case "keys":
					keys = j.field(c, "value")
				case "resave", "saveUninitialized":
					sessionOpts = true
				case "origin":
					origin = j.field(c, "value")
				case "credentials":
					creds = j.field(c, "value")
				}
			}
		}
		// express-session options: { secret: "...", resave: false } signs the session
		// cookie with a key anyone who reads the source knows.
		if secret != nil && sessionOpts {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = "sessionSecret"
			call.x = fn
			call.args = []*expr{j.expr(secret)}
			call.kw = []string{""}
			e.args = append(e.args, call)
		}
		// cookie-session options: { name: "session", keys: ["..."] }.
		if keys != nil && j.kind(keys) == "array" {
			for _, k := range j.named(keys) {
				if j.kind(k) == "string" {
					call := j.mk(exprCall, n)
					fn := j.mk(exprName, n)
					fn.name = "sessionKeys"
					call.x = fn
					call.args = []*expr{j.expr(k)}
					call.kw = []string{""}
					e.args = append(e.args, call)
				}
			}
		}
		// {role: "system", content: x} and {system: x}: request data in an LLM's instructions.
		var role, content *node
		for _, c := range j.named(n) {
			if j.kind(c) != "pair" {
				continue
			}
			switch strings.Trim(j.text(j.field(c, "key")), `"'`) {
			case "role":
				role = j.field(c, "value")
			case "content":
				content = j.field(c, "value")
			case "system", "systemPrompt", "system_prompt", "instructions":
				e.args = append(e.args, j.llmPrompt(c, j.field(c, "value")))
			}
		}
		if role != nil && content != nil && strings.Trim(j.text(role), `"'`) == "system" {
			e.args = append(e.args, j.llmPrompt(n, content))
		}
		if origin != nil && creds != nil {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = "corsConfig"
			call.x = fn
			call.args = []*expr{j.expr(origin), j.expr(creds)}
			call.kw = []string{"", ""}
			e.args = append(e.args, call)
		}
		return e
	case "pair":
		if strings.Trim(j.text(j.field(n, "key")), `"'`) == "$where" {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = "mongoWhere"
			call.x = fn
			call.args = []*expr{j.expr(j.field(n, "value"))}
			call.kw = []string{""}
			return call
		}
		if key := strings.Trim(j.text(j.field(n, "key")), `"'`); (key == "httpOnly" || key == "secure") && j.text(j.field(n, "value")) == "false" {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = "cookieFlag"
			call.x = fn
			return call
		}
		if key := strings.Trim(j.text(j.field(n, "key")), `"'`); key == "autoescape" || key == "noent" {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = key
			call.x = fn
			call.args = []*expr{j.expr(j.field(n, "value"))}
			call.kw = []string{""}
			return call
		}
		// { rejectUnauthorized: false } is a call to a misuse check; any other pair is
		// just its value.
		if key := strings.Trim(j.text(j.field(n, "key")), `"'`); jsPairChecks[key] {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = key
			call.x = fn
			val := j.expr(j.field(n, "value"))
			if key == "algorithms" {
				// ['RS256', 'none']: the check looks for the word in the list's text.
				val = &expr{kind: exprStr, pos: val.pos, str: j.text(j.field(n, "value"))}
			}
			call.args = []*expr{val}
			call.kw = []string{""}
			return call
		}
		return j.other(n, j.expr(j.field(n, "value")))
	case "jsx_attribute":
		// <div dangerouslySetInnerHTML={{__html: x}}>: React's escape hatch, a call to a sink.
		cs := j.named(n)
		if len(cs) == 2 && j.text(cs[0]) == "dangerouslySetInnerHTML" {
			call := j.mk(exprCall, n)
			fn := j.mk(exprName, n)
			fn.name = "dangerouslySetInnerHTML"
			call.x = fn
			call.args = []*expr{j.expr(cs[1])}
			call.kw = []string{""}
			return call
		}
	case "assignment_expression":
		return j.expr(j.field(n, "right"))
	}
	// array, object, pair, jsx, sequence...: the taint of every child.
	e := j.mk(exprOther, n)
	for _, c := range j.named(n) {
		if k := j.kind(c); k == "property_identifier" || k == "type_annotation" {
			continue
		}
		if x := j.expr(c); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

func (j *jsLower) call(n *node, k exprKind, fn *node) *expr {
	// list.includes(x) and set.has(x) are membership checks, the shape of an allowlist.
	if k == exprCall && fn != nil && j.kind(fn) == "member_expression" {
		if m := j.text(j.field(fn, "property")); m == "startsWith" {
			if as := j.named(j.field(n, "arguments")); len(as) == 1 {
				e := j.mk(exprIn, n)
				e.x, e.args = j.expr(as[0]), []*expr{j.expr(j.field(fn, "object"))}
				e.str = "prefix"
				return withWeakAllow(e, j.weakAllow(j.pos(n), j.text(j.field(fn, "object")), j.text(as[0])))
			}
		} else if m == "includes" || m == "has" {
			if as := j.named(j.field(n, "arguments")); len(as) == 1 {
				e := j.mk(exprIn, n)
				e.x, e.args = j.expr(j.field(fn, "object")), []*expr{j.expr(as[0])}
				return withWeakAllow(e, j.weakAllow(j.pos(n), j.text(j.field(fn, "object")), j.text(as[0])))
			}
		}
	}
	if k == exprCall && fn != nil && j.kind(fn) == "member_expression" && j.text(j.field(fn, "property")) == "test" {
		if obj := j.field(fn, "object"); obj != nil && j.kind(obj) == "regex" {
			if as := j.named(j.field(n, "arguments")); len(as) == 1 && strictLiteral(j.text(obj), "/", false) {
				return guardOf(j.pos(n), j.expr(as[0]))
			}
		}
	}
	e := j.mk(k, n)
	e.x = j.expr(fn)
	if e.x == nil {
		e.x = j.mk(exprOther, n)
	}
	for _, a := range j.named(j.field(n, "arguments")) {
		e.args = append(e.args, j.expr(a))
		e.kw = append(e.kw, "")
	}
	// ids.map(id => ...): the callback's first parameter is an element of the receiver.
	if k == exprCall && e.x.kind == exprMember {
		switch e.x.name {
		case "map", "forEach", "filter", "flatMap", "some", "every", "find", "findIndex", "then", "catch", "finally", "subscribe", "pipe":
			for _, a := range e.args {
				if a.kind == exprLambda {
					bindCallback(a, e.x.x)
				}
			}
		}
	}
	// require("x") used inline: require("child_process").exec(cmd)
	if k == exprCall && fn != nil && j.text(fn) == "require" {
		if spec := j.firstString(j.field(n, "arguments")); spec != "" {
			name := j.mk(exprName, n)
			name.name = "\x00require:" + normalizeModule(spec)
			j.mod.imports[name.name] = normalizeModule(spec)
			return name
		}
	}
	return e
}
