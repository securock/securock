package sast

import "strings"

func rubySinks() map[string]sink {
	str := func(k kind, args ...int) sink { return sink{kind: k, args: args, strArg: true} }
	return map[string]sink{
		"system": {kind: kCmd, args: []int{0}, solo: true}, "exec": {kind: kCmd, args: []int{0}, solo: true},
		"spawn": {kind: kCmd, args: []int{0}, solo: true}, "shell_exec": {kind: kCmd, args: []int{0}},
		"IO.popen": {kind: kCmd, args: []int{0}, solo: true}, "Kernel.system": {kind: kCmd, args: []int{0}, solo: true},
		"Kernel.exec": {kind: kCmd, args: []int{0}, solo: true}, "Kernel.spawn": {kind: kCmd, args: []int{0}, solo: true},
		"Open3.capture2": {kind: kCmd, args: []int{0}, solo: true}, "Open3.capture2e": {kind: kCmd, args: []int{0}, solo: true},
		"Open3.capture3": {kind: kCmd, args: []int{0}, solo: true}, "Open3.popen3": {kind: kCmd, args: []int{0}, solo: true},
		"open": {kind: kCmd, args: []int{0}},

		"eval": {kind: kCode, args: []int{0}}, "?.instance_eval": {kind: kCode, args: []int{0}}, "?.class_eval": {kind: kCode, args: []int{0}},
		"?.module_eval": {kind: kCode, args: []int{0}}, "?.constantize": {kind: kCode, args: []int{-1}},
		"ERB.new": {kind: kCode, args: []int{0}}, "?.send": {kind: kCode, args: []int{0}}, "?.public_send": {kind: kCode, args: []int{0}},

		"?.where": str(kSQL, 0), "?.order": str(kSQL, 0), "?.reorder": str(kSQL, 0), "?.group": str(kSQL, 0),
		"?.having": str(kSQL, 0), "?.joins": str(kSQL, 0), "?.pluck": str(kSQL, 0), "?.from": str(kSQL, 0),
		"?.select": str(kSQL, 0), "?.update_all": str(kSQL, 0), "?.delete_all": str(kSQL, 0), "?.find_by_sql": str(kSQL, 0),
		"?.execute": str(kSQL, 0), "?.exec_query": str(kSQL, 0), "?.select_all": str(kSQL, 0), "?.select_value": str(kSQL, 0),
		"?.select_rows": str(kSQL, 0), "?.count_by_sql": str(kSQL, 0),

		"File.read": {kind: kPath, args: []int{0}}, "File.open": {kind: kPath, args: []int{0}}, "File.new": {kind: kPath, args: []int{0}},
		"File.write": {kind: kPath, args: []int{0}}, "File.readlines": {kind: kPath, args: []int{0}}, "File.delete": {kind: kPath, args: []int{0}},
		"File.foreach": {kind: kPath, args: []int{0}}, "File.binread": {kind: kPath, args: []int{0}},
		"IO.read": {kind: kPath, args: []int{0}}, "IO.readlines": {kind: kPath, args: []int{0}}, "IO.foreach": {kind: kPath, args: []int{0}},
		"FileUtils.rm": {kind: kPath, args: []int{0}}, "FileUtils.rm_rf": {kind: kPath, args: []int{0}}, "FileUtils.cp": {kind: kPath, args: []int{0, 1}},
		"FileUtils.mv": {kind: kPath, args: []int{0, 1}}, "FileUtils.mkdir_p": {kind: kPath, args: []int{0}},
		"Dir.glob": {kind: kPath, args: []int{0}}, "Dir.entries": {kind: kPath, args: []int{0}}, "Dir.children": {kind: kPath, args: []int{0}},
		"send_file": {kind: kPath, args: []int{0}}, "require": {kind: kCode, args: []int{0}}, "load": {kind: kCode, args: []int{0}},

		"Net.HTTP.get": {kind: kSSRF, args: []int{0}}, "Net.HTTP.get_response": {kind: kSSRF, args: []int{0}},
		"Net.HTTP.post": {kind: kSSRF, args: []int{0}}, "Net.HTTP.start": {kind: kSSRF, args: []int{0}},
		"URI.open":     {kind: kSSRF, args: []int{0}},
		"HTTParty.get": {kind: kSSRF, args: []int{0}}, "HTTParty.post": {kind: kSSRF, args: []int{0}},
		"Faraday.get": {kind: kSSRF, args: []int{0}}, "RestClient.get": {kind: kSSRF, args: []int{0}},
		"RestClient.post": {kind: kSSRF, args: []int{0}}, "Typhoeus.get": {kind: kSSRF, args: []int{0}},

		"?.html_safe": {kind: kXSS, args: []int{-1}}, "raw": {kind: kXSS, args: []int{0}},
		"redirect_to": {kind: kRedirect, args: []int{0}},

		"Marshal.load": {kind: kDeser, args: []int{0}}, "Marshal.restore": {kind: kDeser, args: []int{0}},
		"YAML.load": {kind: kDeser, args: []int{0}}, "Psych.load": {kind: kDeser, args: []int{0}},
		"YAML.unsafe_load": {kind: kDeser, args: []int{0}}, "Oj.load": {kind: kDeser, args: []int{0}},
		"JSON.load": {kind: kDeser, args: []int{0}},
	}
}

var rubySpec = &langSpec{
	name:  "rb",
	sinks: rubySinks(),
	sanitizers: map[string]kind{
		"Integer": kAll, "Float": kAll, "Rational": kAll, "?.to_i": kAll, "?.to_f": kAll, "?.to_r": kAll, "?.length": kAll,
		"?.size": kAll, "?.count": kAll, "h": kXSS, "html_escape": kXSS, "sanitize": kXSS, "strip_tags": kXSS,
		"CGI.escapeHTML": kXSS, "ERB.Util.html_escape": kXSS, "ERB.Util.h": kXSS, "Rack.Utils.escape_html": kXSS,
		"Shellwords.escape": kCmd, "?.shellescape": kCmd, "File.basename": kPath,
		"CGI.escape": kXSS | kPath | kRedirect | kSSRF, "URI.encode_www_form_component": kXSS | kPath | kRedirect | kSSRF,
		"?.sanitize_sql_array": kSQL, "?.sanitize_sql_like": kSQL, "?.quote": kSQL, "?.sanitize_sql": kSQL,
		"Digest.SHA256.hexdigest": kAll, "Digest.MD5.hexdigest": kAll, "SecureRandom.hex": kAll,
	},
	sourceRoots: map[string]map[string]string{
		"params": {"*": "request data"}, "cookies": {"*": "request cookie"}, "ARGV": {"*": "command-line arguments"},
		"request": {"params": "request data", "headers": "request header", "env": "request header", "cookies": "request cookie",
			"body": "request body", "query_string": "request query", "path": "request path", "url": "request URL",
			"referer": "request header", "user_agent": "request header", "fullpath": "request path", "host": "request host",
			"raw_post": "request body", "GET": "request parameter", "POST": "request body"},
	},
	sourcePrefixes: map[string]string{"gets": "console input", "STDIN": "console input"},
	self:           map[string]bool{"self": true},
	shells:         map[string]bool{},
	mutators:       map[string]bool{"push": true, "append": true, "concat": true, "add": true, "merge!": true, "store": true, "insert": true},
	builtins: func() map[string]bool {
		m := map[string]bool{}
		for k := range rubySinks() {
			if !strings.HasPrefix(k, "?") {
				first, _, _ := strings.Cut(k, ".")
				m[first] = true
			}
		}
		for _, k := range []string{"Integer", "Float", "Rational", "h", "html_escape", "sanitize", "strip_tags", "CGI", "ERB", "Rack", "Shellwords", "URI", "Digest", "SecureRandom", "STDIN", "gets", "File", "IO", "Kernel", "Dir", "FileUtils", "Marshal", "YAML", "Psych", "JSON", "Oj", "Net", "HTTParty", "Faraday", "RestClient", "Typhoeus", "Open3"} {
			m[k] = true
		}
		return m
	}(),
}

func init() { frontends["rb"] = &frontend{spec: rubySpec, lower: lowerRuby} }

type rubyLower struct {
	*lowering
	class string
}

func lowerRuby(l *lowering) *module {
	r := &rubyLower{lowering: l}
	l.mod.top = append(l.mod.top, r.stmts(l.named(l.root))...)
	return l.mod
}

func (r *rubyLower) stmts(ns []*node) []*stmt {
	var out []*stmt
	for _, n := range ns {
		out = append(out, r.stmt(n)...)
	}
	return out
}

func (r *rubyLower) body(n *node) []*stmt {
	if n == nil {
		return nil
	}
	switch r.kind(n) {
	case "body_statement", "then", "else", "do_block", "begin", "block_body":
		return r.stmts(r.named(n))
	case "block":
		// A lambda's body is a block that wraps the statements.
		if b := r.field(n, "body"); b != nil {
			return r.body(b)
		}
		return r.stmts(r.named(n))
	}
	return r.stmt(n)
}

func (r *rubyLower) not(e *expr) *expr {
	return &expr{kind: exprNot, pos: e.pos, x: e}
}

func (r *rubyLower) stmt(n *node) []*stmt {
	switch k := r.kind(n); k {
	case "assignment":
		s := &stmt{kind: stmtAssign, pos: r.pos(n), rhs: r.expr(r.field(n, "right"))}
		s.lhs = r.targets(r.field(n, "left"))
		return []*stmt{s}
	case "operator_assignment":
		s := &stmt{kind: stmtAssign, pos: r.pos(n), aug: true, rhs: r.expr(r.field(n, "right"))}
		s.lhs = r.targets(r.field(n, "left"))
		return []*stmt{s}
	case "return":
		s := &stmt{kind: stmtReturn, pos: r.pos(n)}
		if cs := r.named(n); len(cs) > 0 {
			s.rhs = r.expr(cs[0])
		}
		return []*stmt{s}
	case "break", "next", "redo", "retry":
		return []*stmt{{kind: stmtJump, pos: r.pos(n), loop: true, next: k != "break"}}
	case "if", "unless", "elsif":
		cond := r.expr(r.field(n, "condition"))
		if k == "unless" && cond != nil {
			cond = r.not(cond)
		}
		s := &stmt{kind: stmtIf, pos: r.pos(n), cond: cond, then: r.body(r.field(n, "consequence"))}
		if alt := r.field(n, "alternative"); alt != nil {
			if r.kind(alt) == "elsif" {
				s.els = r.stmt(alt)
			} else {
				s.els = r.body(alt)
			}
		}
		return []*stmt{s}
	case "if_modifier", "unless_modifier":
		cond := r.expr(r.field(n, "condition"))
		if k == "unless_modifier" && cond != nil {
			cond = r.not(cond)
		}
		return []*stmt{{kind: stmtIf, pos: r.pos(n), cond: cond, then: r.stmt(r.field(n, "body"))}}
	case "while", "until", "while_modifier", "until_modifier":
		return []*stmt{{kind: stmtLoop, pos: r.pos(n), then: r.body(r.field(n, "body")), cond: r.expr(r.field(n, "condition"))}}
	case "for":
		s := &stmt{kind: stmtLoop, pos: r.pos(n), then: r.body(r.field(n, "body"))}
		s.lhs = r.targets(r.field(n, "pattern"))
		s.rhs = r.expr(r.field(n, "value"))
		return []*stmt{s}
	case "case":
		s := &stmt{kind: stmtBranch, pos: r.pos(n)}
		for _, c := range r.named(n) {
			if kk := r.kind(c); kk == "when" || kk == "else" || kk == "in_clause" {
				s.arms = append(s.arms, r.body(r.field(c, "body")))
			}
		}
		return []*stmt{s}
	case "begin":
		return []*stmt{{kind: stmtBranch, pos: r.pos(n), arms: [][]*stmt{r.stmts(r.named(n))}}}
	case "method", "singleton_method":
		r.method(n)
	case "class", "module":
		r.classDef(n)
	case "call", "identifier", "element_reference", "binary", "string", "subshell", "conditional", "parenthesized_statements":
		return []*stmt{{kind: stmtExpr, pos: r.pos(n), rhs: r.expr(n)}}
	}
	return nil
}

func (r *rubyLower) targets(n *node) []*expr {
	if n == nil {
		return nil
	}
	switch r.kind(n) {
	case "left_assignment_list", "destructured_left_assignment", "mlhs":
		var out []*expr
		for _, c := range r.named(n) {
			out = append(out, r.targets(c)...)
		}
		return out
	case "splat_parameter", "rest_assignment":
		if cs := r.named(n); len(cs) > 0 {
			return r.targets(cs[0])
		}
	case "call":
		// obj.attr = value is a call to the setter in the syntax tree and an assignment to
		// a member here.
		if recv := r.field(n, "receiver"); recv != nil && r.field(n, "arguments") == nil {
			m := r.mk(exprMember, n)
			m.x = r.expr(recv)
			m.name = r.text(r.field(n, "method"))
			return []*expr{m}
		}
	}
	return []*expr{r.expr(n)}
}

func (r *rubyLower) classDef(n *node) {
	name := r.text(r.field(n, "name"))
	if i := strings.LastIndex(name, "::"); i >= 0 {
		name = name[i+2:]
	}
	prev := r.class
	r.class = name
	defer func() { r.class = prev }()
	if sc := r.field(n, "superclass"); sc != nil {
		for _, c := range r.named(sc) {
			r.mod.supers[name] = append(r.mod.supers[name], r.text(c))
		}
	}
	for _, c := range r.named(r.field(n, "body")) {
		switch r.kind(c) {
		case "method", "singleton_method":
			r.method(c)
		case "class", "module":
			r.classDef(c)
		case "call":
			if r.scopeDef(c) {
				continue
			}
			r.mod.top = append(r.mod.top, r.stmt(c)...)
		default:
			// Class-body statements such as skip_before_action run once, at load time.
			r.mod.top = append(r.mod.top, r.stmt(c)...)
		}
	}
}

// scopeDef registers a Rails scope as a class method: scope :name, ->(args) { body }.
func (r *rubyLower) scopeDef(n *node) bool {
	if r.text(r.field(n, "method")) != "scope" {
		return false
	}
	args := r.named(r.field(n, "arguments"))
	if len(args) < 2 || r.kind(args[0]) != "simple_symbol" {
		return false
	}
	var lambda *expr
	switch r.kind(args[1]) {
	case "lambda":
		lambda = r.blockExpr(args[1])
	case "call":
		if r.text(r.field(args[1], "method")) == "lambda" || r.text(r.field(args[1], "method")) == "proc" {
			if b := r.field(args[1], "block"); b != nil {
				lambda = r.blockExpr(b)
			}
		}
	}
	if lambda == nil || lambda.fn == nil {
		return false
	}
	f := lambda.fn
	f.name, f.class, f.pos = strings.TrimPrefix(r.text(args[0]), ":"), r.class, r.pos(n)
	if len(f.body) > 0 {
		if last := f.body[len(f.body)-1]; last.kind == stmtExpr {
			last.kind = stmtReturn
		}
	}
	r.mod.funcs = append(r.mod.funcs, f)
	return true
}

func (r *rubyLower) method(n *node) {
	f := &funcIR{name: r.text(r.field(n, "name")), class: r.class, pos: r.pos(n)}
	if f.name == "initialize" {
		f.name = "<init>"
	}
	if ps := r.field(n, "parameters"); ps != nil {
		for _, c := range r.named(ps) {
			f.params = append(f.params, r.paramOf(c))
		}
	}
	f.body = r.body(r.field(n, "body"))
	// A Ruby method returns the value of its last expression.
	if len(f.body) > 0 {
		if last := f.body[len(f.body)-1]; last.kind == stmtExpr {
			last.kind = stmtReturn
		}
	}
	r.mod.funcs = append(r.mod.funcs, f)
}

func (r *rubyLower) paramOf(c *node) param {
	switch r.kind(c) {
	case "identifier":
		return param{name: r.text(c)}
	case "optional_parameter", "keyword_parameter", "splat_parameter", "hash_splat_parameter", "block_parameter":
		return param{name: r.text(r.field(c, "name"))}
	}
	return param{name: "\x00unnamed"}
}

func (r *rubyLower) expr(n *node) *expr {
	if n == nil {
		return nil
	}
	switch k := r.kind(n); k {
	case "instance_variable":
		return &expr{kind: exprMember, pos: r.pos(n), name: strings.TrimPrefix(r.text(n), "@"), x: &expr{kind: exprName, pos: r.pos(n), name: "self"}}
	case "identifier", "constant", "self", "class_variable", "global_variable":
		e := r.mk(exprName, n)
		e.name = r.text(n)
		return e
	case "scope_resolution":
		e := r.mk(exprMember, n)
		e.x = r.expr(r.field(n, "scope"))
		e.name = r.text(r.field(n, "name"))
		return e
	case "element_reference":
		cs := r.named(n)
		if len(cs) == 0 {
			break
		}
		e := r.mk(exprIndex, n)
		e.x = r.expr(cs[0])
		for _, c := range cs[1:] {
			e.args = append(e.args, r.expr(c))
		}
		if len(cs) == 2 && (r.kind(cs[1]) == "simple_symbol" || r.kind(cs[1]) == "string") {
			m := r.mk(exprMember, n)
			m.x, m.name = e.x, strings.Trim(strings.TrimPrefix(r.text(cs[1]), ":"), `"'`)
			return m
		}
		return e
	case "call":
		return r.call(n)
	case "string":
		return r.str(n)
	case "subshell":
		call := r.mk(exprCall, n)
		fn := r.mk(exprName, n)
		fn.name = "shell_exec"
		call.x = fn
		call.args = []*expr{r.str(n)}
		call.kw = []string{""}
		return call
	case "integer", "float", "true", "false", "nil", "simple_symbol", "regex", "symbol", "delimited_symbol", "hash_key_symbol":
		e := r.mk(exprNum, n)
		e.str = r.text(n)
		return e
	case "binary":
		l, rr := r.field(n, "left"), r.field(n, "right")
		if l == nil || rr == nil {
			break
		}
		le, re := r.expr(l), r.expr(rr)
		switch strings.TrimSpace(string(r.src[l.EndByte():rr.StartByte()])) {
		case "+", "<<", "%":
			e := r.mk(exprConcat, n)
			e.args = []*expr{le, re}
			return e
		case "&&", "and":
			e := r.mk(exprAnd, n)
			e.args = []*expr{le, re}
			return e
		case "||", "or":
			e := r.mk(exprOr, n)
			e.args = []*expr{le, re}
			return e
		case "=~":
			if r.kind(rr) == "regex" && strictLiteral(r.text(rr), "/", false) {
				return guardOf(r.pos(n), le)
			}
			return r.mk(exprNum, n)
		case "==", "!=", "<", ">", "<=", ">=", "!~", "===":
			return r.bin(n, strings.TrimSpace(string(r.src[l.EndByte():rr.StartByte()])), le, re)
		}
		return r.other(n, le, re)
	case "unary":
		t := strings.TrimSpace(r.text(n))
		if strings.HasPrefix(t, "!") || strings.HasPrefix(t, "not") {
			e := r.mk(exprNot, n)
			if cs := r.named(n); len(cs) > 0 {
				e.x = r.expr(cs[len(cs)-1])
			}
			return e
		}
	case "parenthesized_statements", "splat_argument", "hash_splat_argument", "block_argument":
		if cs := r.named(n); len(cs) > 0 {
			return r.expr(cs[len(cs)-1])
		}
	case "conditional":
		return r.cond(n, r.expr(r.field(n, "condition")), r.expr(r.field(n, "consequence")), r.expr(r.field(n, "alternative")))
	case "lambda", "do_block", "block":
		return r.blockExpr(n)
	case "pair":
		key := strings.TrimPrefix(strings.Trim(r.text(r.field(n, "key")), `":`), ":")
		key = strings.TrimSuffix(key, ":")
		val := r.expr(r.field(n, "value"))
		switch key {
		case "order", "conditions", "group", "having", "joins", "select", "from", "lock":
			// Product.find(:all, :order => params[:o]): the option is raw SQL.
			call := r.mk(exprCall, n)
			fn := r.mk(exprName, n)
			fn.name = "sqlOption"
			call.x = fn
			call.args = []*expr{val}
			call.kw = []string{""}
			return call
		case "session_http_only", "httponly", "http_only", "secure", "session_secure":
			if v, ok := constText(val); ok && v == "false" {
				call := r.mk(exprCall, n)
				fn := r.mk(exprName, n)
				fn.name = "cookieFlag"
				call.x = fn
				return call
			}
		}
		// where(name: x) passes a hash: Other, so a string-only sink skips it.
		return r.other(n, val)
	}
	e := r.mk(exprOther, n)
	for _, c := range r.named(n) {
		if x := r.expr(c); x != nil {
			e.args = append(e.args, x)
		}
	}
	return e
}

func (r *rubyLower) blockExpr(n *node) *expr {
	e := r.mk(exprLambda, n)
	f := &funcIR{pos: r.pos(n)}
	if ps := r.field(n, "parameters"); ps != nil {
		for _, c := range r.named(ps) {
			f.params = append(f.params, r.paramOf(c))
		}
	}
	f.body = r.body(r.field(n, "body"))
	e.fn = f
	return e
}

func (r *rubyLower) str(n *node) *expr {
	var subs []*expr
	var text strings.Builder
	for _, c := range r.named(n) {
		switch r.kind(c) {
		case "interpolation":
			for _, x := range r.named(c) {
				if v := r.expr(x); v != nil {
					subs = append(subs, v)
				}
			}
		case "string_content":
			text.WriteString(r.text(c))
		}
	}
	if len(subs) == 0 {
		e := r.mk(exprStr, n)
		e.str = text.String()
		return e
	}
	e := r.mk(exprConcat, n)
	e.args = subs
	return e
}

func (r *rubyLower) call(n *node) *expr {
	e := r.mk(exprCall, n)
	method := r.text(r.field(n, "method"))
	recv := r.field(n, "receiver")
	if recv == nil {
		fn := r.mk(exprName, n)
		fn.name = method
		e.x = fn
	} else {
		fn := r.mk(exprMember, n)
		fn.x = r.expr(recv)
		fn.name = method
		e.x = fn
	}
	for _, a := range r.named(r.field(n, "arguments")) {
		e.args = append(e.args, r.expr(a))
		e.kw = append(e.kw, "")
	}
	if method == "match?" && len(e.args) == 1 && recv != nil {
		// value.match?(/re/): the receiver is the checked value.
		if as := r.named(r.field(n, "arguments")); len(as) == 1 && r.kind(as[0]) == "regex" && strictLiteral(r.text(as[0]), "/", false) {
			return guardOf(r.pos(n), e.x.x)
		}
	}
	if recv != nil && method == "start_with?" && len(e.args) == 1 {
		in := r.mk(exprIn, n)
		in.x, in.args = e.args[0], []*expr{e.x.x}
		in.str = "prefix"
		if as := r.named(r.field(n, "arguments")); len(as) == 1 {
			return withWeakAllow(in, r.weakAllow(r.pos(n), r.text(recv), r.text(as[0])))
		}
		return in
	}
	if recv != nil && (method == "include?" || method == "member?" || method == "key?" || method == "has_key?") && len(e.args) == 1 {
		in := r.mk(exprIn, n)
		in.x, in.args = e.x.x, []*expr{e.args[0]}
		return in
	}
	if b := r.field(n, "block"); b != nil {
		blk := r.blockExpr(b)
		if recv != nil {
			// items.each { |i| ... }: the block runs over the receiver's elements, so its
			// parameters carry the receiver's taint.
			return r.other(n, e.x.x, r.bindBlock(blk, e.x.x))
		}
		e.args = append(e.args, blk)
		e.kw = append(e.kw, "")
	}
	return e
}

// bindBlock turns the block into a body that first assigns each parameter from the
// iterated value.
func (r *rubyLower) bindBlock(blk *expr, over *expr) *expr {
	f := blk.fn
	var pre []*stmt
	for _, p := range f.params {
		name := &expr{kind: exprName, pos: blk.pos, name: p.name}
		pre = append(pre, &stmt{kind: stmtAssign, pos: blk.pos, lhs: []*expr{name}, rhs: over, binds: true})
	}
	f.params = nil
	f.body = append(pre, f.body...)
	return blk
}
