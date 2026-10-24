package sast

// SQL string escaping is not validation of an unquoted SQL expression. Keep the
// payload tainted, and consume these local facts only at SQL sinks. Assignment,
// branch disagreement and unknown transformations discard the proof.
const (
	phpEscapedSQL kind = 1 << 26
	phpQuotedSQL  kind = 1 << 27
)

func (r *irRun) phpSQLFacts(e *expr, st istate) kind {
	if r.spec.name != "php" || e == nil {
		return 0
	}
	if name, field, ok := r.pathOf(e); ok {
		return st.validated(name, field) & (phpEscapedSQL | phpQuotedSQL)
	}
	if e.kind == exprCall && positionalOnly(e) {
		q, recv, field := r.resolve(e.x, st)
		switch q {
		case "mysqli_real_escape_string":
			if len(e.args) == 2 {
				return phpEscapedSQL
			}
		case "mysql_real_escape_string", "pg_escape_string":
			if len(e.args) == 1 || len(e.args) == 2 {
				return phpEscapedSQL
			}
		}
		if field == "real_escape_string" && recv != nil && len(e.args) == 1 && len(r.targets(e.x, e, st)) == 0 && (r.typeOf(recv, st) == "mysqli" || containsFold(phpDB, rootName(recv))) {
			return phpEscapedSQL
		}
	}
	if e.kind == exprConcat && r.phpSQLQuerySafe(e, st) {
		return phpQuotedSQL
	}
	return 0
}

func (r *irRun) phpSQLQuerySafe(e *expr, st istate) bool {
	if r.spec.name != "php" || e == nil {
		return false
	}
	if name, field, ok := r.pathOf(e); ok {
		return st.validated(name, field)&phpQuotedSQL != 0
	}
	if e.kind != exprConcat || e.str != "." && e.str != "interpolate" {
		return false
	}
	var parts []*expr
	var flatten func(*expr) bool
	flatten = func(x *expr) bool {
		if x == nil || len(parts) >= 256 {
			return false
		}
		if x.kind == exprConcat && (x.str == "." || x.str == "interpolate") {
			for _, arg := range x.args {
				if !flatten(arg) {
					return false
				}
			}
		} else {
			parts = append(parts, x)
		}
		return true
	}
	if !flatten(e) {
		return false
	}
	quoted := false
	previous := byte(0)
	for _, part := range parts {
		if text, known := r.strOf(part); known {
			for i := range len(text) {
				c := text[i]
				// Comments, identifiers and backslash modes require a SQL dialect
				// parser. Do not infer string context from those spellings.
				if c == '\\' || c == 0 || !quoted && (c == '"' || c == '`' || c == '#' || previous == '-' && c == '-' || previous == '/' && c == '*') {
					return false
				}
				if c == '\'' {
					quoted = !quoted
				}
				previous = c
			}
			continue
		}
		if !quoted || r.phpSQLFacts(part, st)&phpEscapedSQL == 0 {
			return false
		}
		previous = 0
	}
	return !quoted
}
