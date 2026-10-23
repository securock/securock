package sast

import "go/token"

// The intermediate representation is what every non-Go frontend lowers its syntax tree
// into, so one taint engine serves all of them. It keeps only what dataflow needs:
// names, member access, calls, string building, assignments and control flow. Anything
// a frontend does not model becomes an exprOther that passes its children's taint on,
// which errs toward reporting rather than toward silence.

type exprKind int

const (
	exprName   exprKind = iota // identifier
	exprMember                 // X.Name
	exprIndex                  // X[Args[0]]
	exprCall                   // X(Args...)
	exprNew                    // new X(Args...)
	exprStr                    // string literal; Str holds the value
	exprNum                    // number, boolean, null: inert
	exprConcat                 // string building: +, template/f-string/interpolation, join
	exprLambda                 // function expression; Fn holds the body
	exprNot                    // !X
	exprAnd                    // Args[0] && Args[1]
	exprOr                     // Args[0] || Args[1]
	exprIn                     // Args[0] is a member of the collection X (a validation form)
	exprBin                    // arithmetic or comparison: op in str, operands in Args
	exprCond                   // x ? Args[0] : Args[1]
	exprOther                  // anything else: taint of the children
	exprObject                 // object/dictionary literal: preserve children's fields
	exprField                  // a named entry of an object; name is the property
)

type expr struct {
	kind  exprKind
	pos   token.Pos
	name  string  // identifier, or member name
	str   string  // string literal value
	guard kind    // classes neutralized by a validation form; zero means all
	x     *expr   // base, callee, or operand
	args  []*expr // call arguments, concat parts, index, or children
	// kw holds the names of keyword arguments, parallel to args (empty for positional).
	kw []string
	fn *funcIR
	// ty is the declared type of an identifier at its declaration, as written.
	ty    string
	local bool // explicitly declared local, even when its type is inferred
}

type stmtKind int

const (
	stmtAssign stmtKind = iota // lhs = rhs
	stmtExpr
	stmtReturn
	stmtJump   // break, continue, throw: control leaves the block
	stmtIf     // cond, then, els
	stmtLoop   // lhs iterates over rhs; body in then
	stmtBranch // several alternative bodies (switch, try/catch, match)
)

type stmt struct {
	kind stmtKind
	pos  token.Pos
	lhs  []*expr
	rhs  *expr
	aug  bool // x += y keeps the old value of x
	cond *expr
	then []*stmt
	els  []*stmt
	arms [][]*stmt
	// loop marks a break or continue: control leaves for the end of the loop, so the
	// state at this point still reaches the code after it.
	loop bool
	next bool // continue/next feeds the next iteration; break only feeds the exit
	// binds marks an assignment the frontend made up (a loop or callback parameter), which
	// must not hide a request object of the same name.
	binds bool
}

type param struct {
	name string
	ty   string
	// source marks a parameter the framework fills from the request: a route handler
	// argument, or a Spring @RequestParam.
	source string
}

type funcIR struct {
	name   string
	class  string // enclosing class, for methods
	params []param
	body   []*stmt
	pos    token.Pos
	// htmlRoute marks a web handler whose returned string is sent as an HTML page
	// (a Flask @app.route function), so what it returns is written to the browser.
	htmlRoute bool
}

// module is one lowered source file.
type module struct {
	lang string
	path string // relative to the scanned root
	// imports maps a local name to the qualified name it stands for:
	// "cp" -> "child_process", "exec" -> "child_process.exec".
	imports map[string]string
	// locals maps a local name to a project file and the name inside it, for imports of
	// the project's own modules.
	locals map[string]localRef
	funcs  []*funcIR
	top    []*stmt // module-level code
	// topStrs caches the module-level string constants (irRun.moduleStrs).
	topStrs map[string]string
	// fields maps class -> field -> declared type, for languages that declare them.
	fields       map[string]map[string]string
	staticFields map[string]bool // Class.field is not part of an instance's state
	// supers maps class -> declared supertypes (extends, implements), so a call through
	// an interface reaches the classes implementing it.
	supers map[string][]string
	// globalCSRF is set when the file registers an antiforgery filter for every action.
	globalCSRF bool
}

type localRef struct {
	spec string // module specifier as written: "./db", "..util", "app.db"
	name string // name inside the module, empty for the module itself
}
