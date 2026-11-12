package remediation

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"github.com/securock/securock/internal/finding"
)

type edit struct {
	start, end, line, column int
	text                     string
}

// tlsEdits uses syntax nodes, so strings and comments that resemble settings
// cannot become patch targets. The anchor is the scanner's finding position.
func tlsEdits(file string, raw []byte, id string) ([]edit, error) {
	var out []edit
	if id == "sast:go/tls-verification-disabled" {
		fs := token.NewFileSet()
		tree, err := parser.ParseFile(fs, file, raw, 0)
		if err != nil {
			return nil, err
		}
		add := func(anchor token.Pos, value ast.Expr, name string) {
			b, ok := value.(*ast.Ident)
			if !ok || name != "InsecureSkipVerify" || b.Name != "true" {
				return
			}
			pos := fs.Position(anchor)
			out = append(out, edit{fs.Position(b.Pos()).Offset, fs.Position(b.End()).Offset, pos.Line, pos.Column, "false"})
		}
		ast.Inspect(tree, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if key, ok := n.Key.(*ast.Ident); ok {
					add(n.Pos(), n.Value, key.Name)
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, lhs := range n.Lhs {
						if key, ok := lhs.(*ast.SelectorExpr); ok {
							add(n.Pos(), n.Rhs[i], key.Sel.Name)
						}
					}
				}
			}
			return true
		})
		return out, nil
	}
	entry := grammars.DetectLanguage(file)
	if entry == nil {
		return nil, fmt.Errorf("unsupported source grammar")
	}
	lang := entry.Language()
	tree, err := gotreesitter.NewParser(lang).Parse(raw)
	if err != nil || tree == nil {
		return nil, fmt.Errorf("cannot parse patch target")
	}
	defer tree.Release()
	if tree.RootNode().HasError() {
		return nil, fmt.Errorf("patch target contains syntax errors")
	}
	var walk func(*gotreesitter.Node, *gotreesitter.Node)
	walk = func(n, call *gotreesitter.Node) {
		kind := n.Type(lang)
		if kind == "call" || kind == "call_expression" {
			call = n
		}
		var value, anchor *gotreesitter.Node
		replacement := ""
		if id == "sast:py/tls-verification-disabled" && filepath.Ext(file) == ".py" && kind == "keyword_argument" && call != nil {
			key, v := n.ChildByFieldName("name", lang), n.ChildByFieldName("value", lang)
			if key != nil && v != nil && key.Text(raw) == "verify" && v.Text(raw) == "False" {
				value, anchor, replacement = v, call, "True"
			}
		}
		if id == "sast:js/tls-verification-disabled" && kind == "pair" {
			key, v := n.ChildByFieldName("key", lang), n.ChildByFieldName("value", lang)
			if key != nil && v != nil && strings.Trim(key.Text(raw), "\"'") == "rejectUnauthorized" && v.Text(raw) == "false" {
				value, anchor, replacement = v, n, "true"
			}
		}
		if value != nil {
			point := anchor.StartPoint()
			out = append(out, edit{int(value.StartByte()), int(value.EndByte()), int(point.Row) + 1, int(point.Column) + 1, replacement})
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i), call)
		}
	}
	walk(tree.RootNode(), nil)
	return out, nil
}

func supportedFix(id string) bool {
	return id == "sast:go/tls-verification-disabled" || id == "sast:py/tls-verification-disabled" || id == "sast:js/tls-verification-disabled"
}

func sameLocation(a, b *finding.Location) bool {
	return a != nil && b != nil && a.File == b.File && a.Line == b.Line && (a.Column == 0 || a.Column == b.Column)
}
