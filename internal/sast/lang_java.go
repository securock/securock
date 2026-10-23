package sast

import (
	"strings"
)

var javaSimpleTypes = func() map[string]string {
	m := map[string]string{}
	add := func(pkg string, names ...string) {
		for _, n := range names {
			m[n] = pkg + "." + n
		}
	}
	add("java.lang", "Runtime", "ProcessBuilder", "Integer", "Long", "Double", "Float", "Boolean", "Short", "String", "Math")
	add("java.sql", "Statement", "PreparedStatement", "Connection", "CallableStatement", "DriverManager")
	add("java.io", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile", "PrintWriter", "File", "ObjectInputStream")
	add("java.nio.file", "Files", "Paths", "Path")
	add("java.net", "URL", "URI", "URLEncoder", "Socket")
	add("javax.servlet.http", "HttpServletRequest", "HttpServletResponse")
	add("jakarta.servlet.http", "HttpServletRequest", "HttpServletResponse")
	add("javax.persistence", "EntityManager")
	add("jakarta.persistence", "EntityManager")
	add("org.springframework.jdbc.core", "JdbcTemplate")
	add("org.springframework.jdbc.core.namedparam", "NamedParameterJdbcTemplate")
	add("org.springframework.web.client", "RestTemplate")
	add("org.hibernate", "Session")
	add("java.util", "UUID")
	add("java.util.zip", "ZipEntry", "ZipInputStream", "ZipFile")
	add("java.util.jar", "JarEntry", "JarInputStream")
	return m
}()

func javaSinks() map[string]sink {
	m := map[string]sink{
		"java.lang.Runtime.exec":           {kind: kCmd, args: []int{0}},
		"java.lang.ProcessBuilder":         {kind: kCmd, args: []int{0}, shellFrom: 1},
		"java.io.FileInputStream":          {kind: kPath, args: []int{0}},
		"java.io.FileOutputStream":         {kind: kPath, args: []int{0}},
		"java.io.FileReader":               {kind: kPath, args: []int{0}},
		"java.io.FileWriter":               {kind: kPath, args: []int{0}},
		"java.io.RandomAccessFile":         {kind: kPath, args: []int{0}},
		"java.nio.file.Files.readAllBytes": {kind: kPath, args: []int{0}}, "java.nio.file.Files.readString": {kind: kPath, args: []int{0}},
		"java.nio.file.Files.readAllLines": {kind: kPath, args: []int{0}}, "java.nio.file.Files.newInputStream": {kind: kPath, args: []int{0}},
		"java.nio.file.Files.newBufferedReader": {kind: kPath, args: []int{0}}, "java.nio.file.Files.write": {kind: kPath, args: []int{0}},
		"java.nio.file.Files.writeString": {kind: kPath, args: []int{0}}, "java.nio.file.Files.delete": {kind: kPath, args: []int{0}},
		"java.nio.file.Files.deleteIfExists": {kind: kPath, args: []int{0}}, "java.nio.file.Files.copy": {kind: kPath, args: []int{0, 1}},
		"java.nio.file.Files.move": {kind: kPath, args: []int{0, 1}}, "java.nio.file.Files.lines": {kind: kPath, args: []int{0}},
		"org.springframework.core.io.FileSystemResource": {kind: kPath, args: []int{0}},

		"java.net.URL": {kind: kSSRF, args: []int{0}}, "java.net.URI.create": {kind: kSSRF, args: []int{0}},
		"java.net.Socket": {kind: kSSRF, args: []int{0}},
		"org.springframework.web.client.RestTemplate.getForObject":  {kind: kSSRF, args: []int{0}},
		"org.springframework.web.client.RestTemplate.getForEntity":  {kind: kSSRF, args: []int{0}},
		"org.springframework.web.client.RestTemplate.postForObject": {kind: kSSRF, args: []int{0}},
		"org.springframework.web.client.RestTemplate.exchange":      {kind: kSSRF, args: []int{0}},
		"org.apache.http.client.methods.HttpGet":                    {kind: kSSRF, args: []int{0}},
		"org.apache.http.client.methods.HttpPost":                   {kind: kSSRF, args: []int{0}},

		"java.io.PrintWriter.println": {kind: kXSS, args: []int{0}}, "java.io.PrintWriter.print": {kind: kXSS, args: []int{0}},
		"java.io.PrintWriter.write": {kind: kXSS, args: []int{0}}, "java.io.PrintWriter.printf": {kind: kXSS, args: []int{0}, rest: true},
		"java.io.PrintWriter.append": {kind: kXSS, args: []int{0}},

		"javax.servlet.http.HttpServletResponse.sendRedirect":   {kind: kRedirect, args: []int{0}},
		"jakarta.servlet.http.HttpServletResponse.sendRedirect": {kind: kRedirect, args: []int{0}},
		"org.springframework.web.servlet.view.RedirectView":     {kind: kRedirect, args: []int{0}},

		"java.io.ObjectInputStream":                {kind: kDeser, args: []int{0}},
		"org.yaml.snakeyaml.Yaml.load":             {kind: kDeser, args: []int{0}},
		"com.thoughtworks.xstream.XStream.fromXML": {kind: kDeser, args: []int{0}},
		"javax.script.ScriptEngine.eval":           {kind: kCode, args: []int{0}},
		"groovy.lang.GroovyShell.evaluate":         {kind: kCode, args: []int{0}},
		"?.parseExpression":                        {kind: kCode, args: []int{0}},

		"?.executeQuery": {kind: kSQL, args: []int{0}}, "?.executeUpdate": {kind: kSQL, args: []int{0}},
		"?.prepareStatement": {kind: kSQL, args: []int{0}}, "?.prepareCall": {kind: kSQL, args: []int{0}},
		"?.createQuery": {kind: kSQL, args: []int{0}}, "?.createNativeQuery": {kind: kSQL, args: []int{0}},
		"?.createSQLQuery": {kind: kSQL, args: []int{0}}, "?.addBatch": {kind: kSQL, args: []int{0}},
		"?.queryForObject": {kind: kSQL, args: []int{0}}, "?.queryForList": {kind: kSQL, args: []int{0}},
		"?.query":   {kind: kSQL, args: []int{0}, recv: []string{"jdbcTemplate", "jdbc", "template", "namedParameterJdbcTemplate"}},
		"?.update":  {kind: kSQL, args: []int{0}, recv: []string{"jdbcTemplate", "jdbc", "template", "namedParameterJdbcTemplate"}},
		"?.execute": {kind: kSQL, args: []int{0}, recv: []string{"statement", "stmt", "st", "jdbcTemplate", "jdbc", "template"}},
	}
	return m
}

var javaRequestMethods = map[string]string{
	"getParameter": "request parameter", "getParameterValues": "request parameter", "getParameterMap": "request parameter",
	"getHeader": "request header", "getHeaders": "request header", "getQueryString": "request query",
	"getRequestURI": "request URL", "getRequestURL": "request URL", "getPathInfo": "request path",
	"getServletPath": "request path", "getCookies": "request cookie", "getInputStream": "request body",
	"getReader": "request body", "getPart": "uploaded file", "getRemoteUser": "request user",
}

var javaSpec = &langSpec{
	name:  "java",
	sinks: javaSinks(),
	sanitizers: map[string]kind{
		"java.lang.Integer.parseInt": kAll, "java.lang.Integer.valueOf": kAll, "java.lang.Long.parseLong": kAll,
		"java.lang.Long.valueOf": kAll, "java.lang.Double.parseDouble": kAll, "java.lang.Float.parseFloat": kAll,
		"java.lang.Boolean.parseBoolean": kAll, "java.util.UUID.fromString": kAll,
		"org.springframework.web.util.HtmlUtils.htmlEscape":      kXSS,
		"org.apache.commons.text.StringEscapeUtils.escapeHtml4":  kXSS,
		"org.apache.commons.lang3.StringEscapeUtils.escapeHtml4": kXSS,
		"org.owasp.encoder.Encode.forHtml":                       kXSS, "org.owasp.encoder.Encode.forHtmlContent": kXSS,
		"org.owasp.encoder.Encode.forHtmlAttribute": kXSS, "org.owasp.encoder.Encode.forJavaScript": kXSS,
		"org.owasp.encoder.Encode.forUriComponent":    kXSS | kPath | kRedirect | kSSRF,
		"java.net.URLEncoder.encode":                  kXSS | kPath | kRedirect | kSSRF,
		"org.apache.commons.io.FilenameUtils.getName": kPath, "?.getFileName": kPath,
	},
	sourceMethods: javaRequestMethods,
	sourceRoots:   map[string]map[string]string{},
	returns: map[string]string{
		"java.sql.Connection.createStatement":                "java.sql.Statement",
		"java.sql.DriverManager.getConnection":               "java.sql.Connection",
		"java.lang.Runtime.getRuntime":                       "java.lang.Runtime",
		"javax.servlet.http.HttpServletResponse.getWriter":   "java.io.PrintWriter",
		"jakarta.servlet.http.HttpServletResponse.getWriter": "java.io.PrintWriter",
	},
	mutators:    map[string]bool{"append": true, "add": true, "put": true, "addAll": true, "insert": true, "offer": true, "push": true, "putAll": true},
	self:        map[string]bool{"this": true},
	shells:      map[string]bool{"sh": true, "bash": true, "cmd": true, "cmd.exe": true, "/bin/sh": true, "/bin/bash": true, "powershell": true},
	simpleTypes: javaSimpleTypes,
}

func init() { frontends["java"] = &frontend{spec: javaSpec, lower: lowerJava} }

type javaLower struct {
	*lowering
	class string
}

func lowerJava(l *lowering) *module {
	j := &javaLower{lowering: l}
	for _, c := range l.named(l.root) {
		switch l.kind(c) {
		case "import_declaration":
			j.importDecl(c)
		case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
			j.classDecl(c)
		}
	}
	return l.mod
}

func (j *javaLower) importDecl(n *node) {
	name := ""
	for _, c := range j.named(n) {
		if j.kind(c) == "scoped_identifier" || j.kind(c) == "identifier" {
			name = j.text(c)
		}
	}
	if name == "" || strings.Contains(j.text(n), "*") {
		return
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		j.mod.imports[name[i+1:]] = name
	}
}

func (j *javaLower) classDecl(n *node) {
	name := j.text(j.field(n, "name"))
	prev := j.class
	j.class = name
	defer func() { j.class = prev }()
	// supertypes
	for _, f := range []string{"superclass", "interfaces", "extends_interfaces"} {
		if s := j.field(n, f); s != nil {
			j.collectTypes(s, name)
		}
	}
	for _, c := range j.named(n) {
		if k := j.kind(c); k == "super_interfaces" || k == "extends_interfaces" {
			j.collectTypes(c, name)
		}
	}
	body := j.field(n, "body")
	for _, m := range j.named(body) {
		switch j.kind(m) {
		case "field_declaration":
			ty := j.typeName(j.field(m, "type"))
			for _, d := range j.named(m) {
				if j.kind(d) == "variable_declarator" {
					if j.mod.fields[name] == nil {
						j.mod.fields[name] = map[string]string{}
					}
					j.mod.fields[name][j.text(j.field(d, "name"))] = ty
				}
			}
		case "method_declaration", "constructor_declaration":
			j.method(m, name)
		case "class_declaration", "interface_declaration", "enum_declaration":
			j.classDecl(m)
		}
	}
}

func (j *javaLower) collectTypes(n *node, class string) {
	var walk func(*node)
	walk = func(x *node) {
		if k := j.kind(x); k == "type_identifier" || k == "scoped_type_identifier" {
			j.mod.supers[class] = append(j.mod.supers[class], j.typeName(x))
			return
		}
		for _, c := range j.named(x) {
			walk(c)
		}
	}
	walk(n)
}

// typeName is the simple name of a type, without generics or array brackets.
func (j *javaLower) typeName(n *node) string {
	if n == nil {
		return ""
	}
	s := j.text(n)
	if i := strings.IndexAny(s, "<["); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

var javaSourceAnnotations = map[string]string{
	"RequestParam": "request parameter", "PathVariable": "request path", "RequestBody": "request body",
	"RequestHeader": "request header", "CookieValue": "request cookie", "ModelAttribute": "request parameter",
	"QueryParam": "request parameter", "PathParam": "request path", "FormParam": "request body",
	"HeaderParam": "request header", "CookieParam": "request cookie", "RequestPart": "uploaded file",
}

func (j *javaLower) method(m *node, class string) {
	f := &funcIR{name: j.text(j.field(m, "name")), class: class, pos: j.pos(m)}
	if j.kind(m) == "constructor_declaration" {
		f.name = "<init>"
	}
	isMain := f.name == "main"
	if ps := j.field(m, "parameters"); ps != nil {
		for _, p := range j.named(ps) {
			if j.kind(p) != "formal_parameter" && j.kind(p) != "spread_parameter" {
				continue
			}
			pr := param{name: j.text(j.field(p, "name")), ty: j.typeName(j.field(p, "type"))}
			if pr.name == "" {
				for _, c := range j.named(p) {
					if j.kind(c) == "variable_declarator" {
						pr.name = j.text(j.field(c, "name"))
					}
				}
			}
			for _, mod := range j.named(p) {
				if j.kind(mod) != "modifiers" {
					continue
				}
				for _, a := range j.named(mod) {
					if desc, ok := javaSourceAnnotations[j.text(j.field(a, "name"))]; ok {
						pr.source = desc
					}
				}
			}
			if isMain && pr.name == "args" {
				pr.source = "command-line arguments"
			}
			f.params = append(f.params, pr)
		}
	}
	f.body = j.block(j.field(m, "body"))
	j.mod.funcs = append(j.mod.funcs, f)
}

func (j *javaLower) block(n *node) []*stmt {
	if n == nil {
		return nil
	}
	switch j.kind(n) {
	case "block", "constructor_body":
		var out []*stmt
		for _, c := range j.named(n) {
			out = append(out, j.stmt(c)...)
		}
		return out
	}
	return j.stmt(n)
}

func (j *javaLower) stmt(n *node) []*stmt {
	switch k := j.kind(n); k {
	case "expression_statement":
		var out []*stmt
		for _, c := range j.named(n) {
			if kk := j.kind(c); kk == "assignment_expression" {
				out = append(out, j.assignment(c))
			} else {
				out = append(out, &stmt{kind: stmtExpr, pos: j.pos(c), rhs: j.expr(c)})
			}
		}
		return out
	case "local_variable_declaration":
		ty := j.typeName(j.field(n, "type"))
		var out []*stmt
		for _, d := range j.named(n) {
			if j.kind(d) != "variable_declarator" {
				continue
			}
			v := j.field(d, "value")
			name := j.mk(exprName, d)
			name.name = j.text(j.field(d, "name"))
			if ty != "var" {
				name.ty = ty
			}
			if v == nil {
				// "ZipEntry e;" assigned later in a loop condition: keep the type.
				if ty != "var" {
					out = append(out, &stmt{kind: stmtAssign, pos: j.pos(d), lhs: []*expr{name}})
				}
				continue
			}
			out = append(out, &stmt{kind: stmtAssign, pos: j.pos(d), lhs: []*expr{name}, rhs: j.expr(v)})
		}
		return out
	case "return_statement":
		s := &stmt{kind: stmtReturn, pos: j.pos(n)}
		if cs := j.named(n); len(cs) > 0 {
			s.rhs = j.expr(cs[0])
		}
		return []*stmt{s}
	case "throw_statement", "break_statement", "continue_statement", "yield_statement":
		return []*stmt{{kind: stmtJump, pos: j.pos(n)}}
	case "if_statement":
		s := &stmt{kind: stmtIf, pos: j.pos(n), cond: j.expr(j.field(n, "condition")), then: j.block(j.field(n, "consequence"))}
		if alt := j.field(n, "alternative"); alt != nil {
			s.els = j.block(alt)
		}
		return []*stmt{s}
	case "enhanced_for_statement":
		name := j.mk(exprName, n)
		name.name = j.text(j.field(n, "name"))
		name.ty = j.typeName(j.field(n, "type"))
		return []*stmt{{kind: stmtLoop, pos: j.pos(n), lhs: []*expr{name}, rhs: j.expr(j.field(n, "value")), then: j.block(j.field(n, "body"))}}
	case "for_statement":
		var out []*stmt
		if init := j.field(n, "init"); init != nil {
			out = append(out, j.stmt(init)...)
		}
		return append(out, &stmt{kind: stmtBranch, pos: j.pos(n), arms: [][]*stmt{j.block(j.field(n, "body"))}})
	case "while_statement", "do_statement":
		return []*stmt{{kind: stmtBranch, pos: j.pos(n), arms: [][]*stmt{j.block(j.field(n, "body"))}}}
	case "block", "synchronized_statement", "labeled_statement":
		var out []*stmt
		for _, c := range j.named(n) {
			out = append(out, j.stmt(c)...)
		}
		return []*stmt{{kind: stmtBranch, pos: j.pos(n), arms: [][]*stmt{out}}}
	case "try_statement", "try_with_resources_statement":
		s := &stmt{kind: stmtBranch, pos: j.pos(n)}
		var pre []*stmt
		if res := j.field(n, "resources"); res != nil {
			for _, r := range j.named(res) {
				if j.kind(r) == "resource" {
					name := j.mk(exprName, r)
					name.name = j.text(j.field(r, "name"))
					if v := j.field(r, "value"); v != nil && name.name != "" {
						pre = append(pre, &stmt{kind: stmtAssign, pos: j.pos(r), lhs: []*expr{name}, rhs: j.expr(v)})
					}
				}
			}
		}
		s.arms = append(s.arms, append(pre, j.block(j.field(n, "body"))...))
		for _, c := range j.named(n) {
			switch j.kind(c) {
			case "catch_clause":
				s.arms = append(s.arms, j.block(j.field(c, "body")))
			case "finally_clause":
				for _, cc := range j.named(c) {
					s.arms = append(s.arms, j.block(cc))
				}
			}
		}
		return []*stmt{s}
	case "switch_expression", "switch_statement":
		s := &stmt{kind: stmtBranch, pos: j.pos(n)}
		if b := j.field(n, "body"); b != nil {
			for _, g := range j.named(b) {
				var arm []*stmt
				for _, c := range j.named(g) {
					if kk := j.kind(c); kk != "switch_label" {
						arm = append(arm, j.stmt(c)...)
					}
				}
				s.arms = append(s.arms, arm)
			}
		}
		return []*stmt{s}
	}
	return nil
}

func (j *javaLower) assignment(n *node) *stmt {
	s := &stmt{kind: stmtAssign, pos: j.pos(n), rhs: j.expr(j.field(n, "right"))}
	s.lhs = []*expr{j.expr(j.field(n, "left"))}
	s.aug = strings.TrimSpace(string(j.src[j.field(n, "left").EndByte():j.field(n, "right").StartByte()])) != "="
	return s
}

func (j *javaLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch k := j.kind(n); k {
	case "identifier", "this", "super", "type_identifier":
		e := j.mk(exprName, n)
		e.name = j.text(n)
		return e
	case "field_access":
		e := j.mk(exprMember, n)
		e.x = j.expr(j.field(n, "object"))
		e.name = j.text(j.field(n, "field"))
		return e
	case "scoped_identifier":
		e := j.mk(exprMember, n)
		e.x = j.expr(j.field(n, "scope"))
		e.name = j.text(j.field(n, "name"))
		return e
	case "array_access":
		e := j.mk(exprIndex, n)
		e.x = j.expr(j.field(n, "array"))
		e.args = []*expr{j.expr(j.field(n, "index"))}
		return e
	case "method_invocation":
		return j.invoke(n)
	case "object_creation_expression":
		e := j.mk(exprNew, n)
		t := j.mk(exprName, n)
		t.name = j.typeName(j.field(n, "type"))
		e.x = t
		for _, a := range j.named(j.field(n, "arguments")) {
			e.args = append(e.args, j.expr(a))
			e.kw = append(e.kw, "")
		}
		return e
	case "string_literal":
		e := j.mk(exprStr, n)
		for _, c := range j.named(n) {
			if j.kind(c) == "string_fragment" || j.kind(c) == "escape_sequence" {
				e.str += j.text(c)
			}
		}
		return e
	case "decimal_integer_literal", "hex_integer_literal", "decimal_floating_point_literal", "true", "false", "null_literal", "character_literal":
		e := j.mk(exprNum, n)
		e.str = j.text(n)
		return e
	case "binary_expression":
		l, r := j.expr(j.field(n, "left")), j.expr(j.field(n, "right"))
		switch strings.TrimSpace(j.text(j.field(n, "operator"))) {
		case "+":
			e := j.mk(exprConcat, n)
			e.args = []*expr{l, r}
			return e
		case "&&":
			e := j.mk(exprAnd, n)
			e.args = []*expr{l, r}
			return e
		case "||":
			e := j.mk(exprOr, n)
			e.args = []*expr{l, r}
			return e
		case "==", "!=", "<", ">", "<=", ">=":
			return j.mk(exprNum, n)
		}
		return j.other(n, l, r)
	case "unary_expression":
		if strings.TrimSpace(j.text(j.field(n, "operator"))) == "!" {
			e := j.mk(exprNot, n)
			e.x = j.expr(j.field(n, "operand"))
			return e
		}
		return j.other(n, j.expr(j.field(n, "operand")))
	case "parenthesized_expression", "cast_expression":
		cs := j.named(n)
		if len(cs) > 0 {
			return j.expr(cs[len(cs)-1])
		}
	case "ternary_expression":
		return j.other(n, j.expr(j.field(n, "consequence")), j.expr(j.field(n, "alternative")))
	case "assignment_expression":
		return j.expr(j.field(n, "right"))
	case "lambda_expression":
		e := j.mk(exprLambda, n)
		f := &funcIR{pos: j.pos(n)}
		if ps := j.field(n, "parameters"); ps != nil {
			if j.kind(ps) == "identifier" {
				f.params = append(f.params, param{name: j.text(ps)})
			}
			for _, c := range j.named(ps) {
				if j.kind(c) == "identifier" {
					f.params = append(f.params, param{name: j.text(c)})
				} else if j.kind(c) == "formal_parameter" {
					f.params = append(f.params, param{name: j.text(j.field(c, "name"))})
				}
			}
		}
		if b := j.field(n, "body"); b != nil {
			if j.kind(b) == "block" {
				f.body = j.block(b)
			} else {
				f.body = []*stmt{{kind: stmtReturn, pos: j.pos(b), rhs: j.expr(b)}}
			}
		}
		e.fn = f
		return e
	}
	e := j.mk(exprOther, n)
	for _, c := range j.named(n) {
		if x := j.expr(c); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

func (j *javaLower) invoke(n *node) *expr {
	name := j.text(j.field(n, "name"))
	args := j.named(j.field(n, "arguments"))
	// list.contains(x) / set.contains(x) is the membership check of an allowlist.
	obj := j.field(n, "object")
	if obj != nil && name == "startsWith" && len(args) == 1 {
		e := j.mk(exprIn, n)
		e.x, e.args = j.expr(args[0]), []*expr{j.expr(obj)}
		return e
	}
	if obj != nil && name == "contains" && len(args) == 1 {
		e := j.mk(exprIn, n)
		e.x, e.args = j.expr(obj), []*expr{j.expr(args[0])}
		return e
	}
	if obj != nil && name == "matches" && len(args) == 1 && j.kind(args[0]) == "string_literal" {
		if lit := j.expr(args[0]); lit.kind == exprStr && strictLiteral(lit.str, "", true) {
			return guardOf(j.pos(n), j.expr(obj))
		}
	}
	fn := j.mk(exprMember, n)
	fn.name = name
	if obj != nil {
		fn.x = j.expr(obj)
	} else {
		self := j.mk(exprName, n)
		self.name = "this"
		fn.x = self
	}
	e := j.mk(exprCall, n)
	e.x = fn
	for _, a := range args {
		e.args = append(e.args, j.expr(a))
		e.kw = append(e.kw, "")
	}
	// String.format("...%s", x) builds a string out of its arguments.
	if obj != nil && j.text(obj) == "String" && (name == "format" || name == "join") {
		c := j.mk(exprConcat, n)
		c.args = e.args
		return c
	}
	if name == "append" || name == "concat" || name == "toString" || name == "toLowerCase" || name == "toUpperCase" || name == "trim" {
		return e
	}
	return e
}
