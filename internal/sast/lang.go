package sast

import (
	"go/token"
	"path/filepath"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// A frontend turns one source file into the shared IR. Everything it does not
// understand becomes exprOther, so a construct it misses widens the taint instead of
// hiding it.
type frontend struct {
	spec  *langSpec
	lower func(l *lowering) *module
}

var frontends = map[string]*frontend{} // by language id, filled by each lang_*.go

// extensions maps a file extension to the grammar and the frontend language id.
var extensions = map[string][2]string{
	".js": {"javascript", "js"}, ".jsx": {"javascript", "js"}, ".mjs": {"javascript", "js"}, ".cjs": {"javascript", "js"},
	".ts": {"typescript", "js"}, ".tsx": {"tsx", "js"},
	".py":   {"python", "py"},
	".java": {"java", "java"},
	".php":  {"php", "php"},
	".rb":   {"ruby", "rb"},
}

// skippedFile reports files that are not first-party source: minified bundles,
// declarations, and tests.
func skippedFile(name string) bool {
	low := strings.ToLower(name)
	switch {
	case strings.HasSuffix(low, ".min.js"), strings.HasSuffix(low, ".d.ts"), strings.HasSuffix(low, ".bundle.js"):
		return true
	case strings.Contains(low, ".test."), strings.Contains(low, ".spec."), strings.HasPrefix(low, "test_"), strings.HasSuffix(low, "_test.py"), strings.HasSuffix(low, "_spec.rb"), strings.HasSuffix(low, "test.java"), strings.HasSuffix(low, "tests.java"), strings.HasSuffix(low, "test.php"):
		return true
	}
	return false
}

// skippedDirs are directories of vendored, generated or installed code.
var skippedDirs = map[string]bool{
	"dist": true, "build": true, "out": true, "coverage": true, "target": true,
	"__pycache__": true, "venv": true, "site-packages": true, "bower_components": true,
	"__tests__": true, "tests": true, "test": true, "spec": true, "e2e": true,
}

type lowering struct {
	src  []byte
	lang *gotreesitter.Language
	file *token.File
	mod  *module
	root *gotreesitter.Node
}

func (l *lowering) text(n *gotreesitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Text(l.src)
}

func (l *lowering) kind(n *gotreesitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Type(l.lang)
}

func (l *lowering) pos(n *gotreesitter.Node) token.Pos {
	if n == nil {
		return token.NoPos
	}
	return l.file.Pos(int(n.StartByte()))
}

func (l *lowering) field(n *gotreesitter.Node, name string) *gotreesitter.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName(name, l.lang)
}

// named returns the named children, skipping comments.
func (l *lowering) named(n *gotreesitter.Node) []*gotreesitter.Node {
	if n == nil {
		return nil
	}
	var out []*gotreesitter.Node
	for i := range n.NamedChildCount() {
		c := n.NamedChild(i)
		if c != nil && !strings.Contains(l.kind(c), "comment") {
			out = append(out, c)
		}
	}
	return out
}

func (l *lowering) mk(k exprKind, n *gotreesitter.Node) *expr {
	return &expr{kind: k, pos: l.pos(n)}
}

func (l *lowering) other(n *gotreesitter.Node, children ...*expr) *expr {
	e := l.mk(exprOther, n)
	for _, c := range children {
		if c != nil {
			e.args = append(e.args, c)
		}
	}
	return e
}

// parse lowers one source file. ok is false when the grammar is missing or the file has
// syntax errors the parser could not recover from.
func parseFile(fset *token.FileSet, abs, rel string, src []byte) (m *module, hadError bool, err error) {
	ext := strings.ToLower(filepath.Ext(abs))
	info, ok := extensions[ext]
	if !ok {
		return nil, false, nil
	}
	fe := frontends[info[1]]
	if fe == nil {
		return nil, false, nil
	}
	entry := grammars.DetectLanguage("x" + ext)
	if entry == nil {
		return nil, true, nil
	}
	lang := entry.Language()
	tree, err := gotreesitter.NewParser(lang).Parse(src)
	if err != nil || tree == nil {
		return nil, true, err
	}
	file := fset.AddFile(abs, -1, len(src))
	file.SetLinesForContent(src)
	root := tree.RootNode()
	l := &lowering{src: src, lang: lang, file: file, root: root}
	l.mod = &module{lang: info[1], path: rel, imports: map[string]string{}, locals: map[string]localRef{}, fields: map[string]map[string]string{}, supers: map[string][]string{}}
	hadError = root.HasError()
	defer func() {
		if recover() != nil {
			m, hadError = nil, true
		}
	}()
	return fe.lower(l), hadError, nil
}

// bindCallback makes the first parameter of a lambda an element of the collection it is
// applied to, so ids.map(id => ...) sees the taint of ids.
func bindCallback(lambda *expr, over *expr) {
	f := lambda.fn
	if f == nil || len(f.params) == 0 || f.params[0].name == "" {
		return
	}
	name := &expr{kind: exprName, pos: lambda.pos, name: f.params[0].name}
	f.body = append([]*stmt{{kind: stmtAssign, pos: lambda.pos, lhs: []*expr{name}, rhs: over, binds: true}}, f.body...)
}
