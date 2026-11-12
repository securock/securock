package sast

import (
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Symbol names a vulnerable API in an independently supplied advisory. Symbols
// use fully qualified Go names, for example net/http.ListenAndServe.
type Symbol struct {
	ID   string `json:"id"`
	Name string `json:"symbol"`
}

type callEdge struct {
	to       string
	location finding.Location
}

// Calls reports potential direct-call paths from explicit entrypoints. Missing
// paths remain unknown: callbacks, interfaces, reflection and external bodies
// prevent proving that a vulnerable API is unreachable.
func Calls(root string, entries []string, symbols []Symbol) (finding.Report, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return finding.New("reachability", nil), err
	}
	fs := token.NewFileSet()
	pkgs, _, _, _, _, gaps, err := load(fs, abs)
	if err != nil {
		return finding.New("reachability", nil), err
	}
	im := &splitImporter{fset: fs, other: importer.ForCompiler(fs, "source", nil).(types.ImporterFrom), own: map[string]*pkg{}}
	for _, p := range pkgs {
		im.own[p.path] = p
	}
	for _, p := range pkgs {
		im.check(p)
	}
	graph := map[string][]callEdge{}
	known := map[string]bool{}
	location := func(pos token.Pos) finding.Location {
		p := fs.Position(pos)
		rel, _ := filepath.Rel(abs, p.Filename)
		return finding.Location{File: filepath.ToSlash(rel), Line: p.Line, Column: p.Column}
	}
	for _, p := range pkgs {
		for _, file := range p.files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				obj, _ := p.info.Defs[fd.Name].(*types.Func)
				if obj == nil {
					continue
				}
				from := obj.FullName()
				known[from] = true
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					// Nested closures may escape rather than execute at their declaration.
					if _, ok := n.(*ast.FuncLit); ok {
						return false
					}
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					fun := call.Fun
					switch e := fun.(type) {
					case *ast.IndexExpr:
						fun = e.X
					case *ast.IndexListExpr:
						fun = e.X
					}
					var target types.Object
					switch e := fun.(type) {
					case *ast.Ident:
						target = p.info.Uses[e]
					case *ast.SelectorExpr:
						if sel := p.info.Selections[e]; sel != nil {
							// Interface dispatch needs a points-to analysis; do not choose one implementation.
							if _, ok := sel.Recv().Underlying().(*types.Interface); ok {
								return true
							}
							target = sel.Obj()
						} else {
							target = p.info.Uses[e.Sel]
						}
					}
					if fn, ok := target.(*types.Func); ok {
						graph[from] = append(graph[from], callEdge{fn.FullName(), location(call.Pos())})
					}
					return true
				})
			}
		}
	}
	for name := range graph {
		sort.Slice(graph[name], func(i, j int) bool {
			a, b := graph[name][i], graph[name][j]
			if a.to != b.to {
				return a.to < b.to
			}
			if a.location.File != b.location.File {
				return a.location.File < b.location.File
			}
			return a.location.Line < b.location.Line
		})
	}
	paths := map[string][]finding.Step{}
	queue := []string{}
	sorted := append([]string(nil), entries...)
	sort.Strings(sorted)
	out := []finding.Finding{}
	for _, entry := range sorted {
		entry = strings.TrimSpace(entry)
		if !known[entry] {
			out = append(out, finding.Finding{ID: "reachability:entry-unavailable", Severity: finding.SeverityInfo, Subject: entry, Title: "Entrypoint could not be resolved"})
			continue
		}
		paths[entry] = []finding.Step{}
		queue = append(queue, entry)
	}
	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]
		for _, edge := range graph[from] {
			if _, ok := paths[edge.to]; ok {
				continue
			}
			paths[edge.to] = append(append([]finding.Step(nil), paths[from]...), finding.Step{Location: edge.location, Message: from + " calls " + edge.to})
			queue = append(queue, edge.to)
		}
	}
	for _, symbol := range symbols {
		name := symbol.Name
		trace, ok := paths[name]
		f := finding.Finding{ID: "reachability:symbol-unknown", Severity: finding.SeverityInfo, Subject: symbol.ID + "/" + symbol.Name, Title: "No resolved direct-call path to the advisory symbol", Detail: "Unknown does not mean unreachable. Dynamic dispatch, callbacks, closures, external bodies and build variants are not exhaustively modeled.", Remediation: "Review dynamic entrypoints and retain the advisory severity until stronger evidence exists."}
		if ok {
			f.ID = "reachability:symbol-reachable"
			f.Title = "Potential direct-call path reaches the advisory symbol"
			f.Detail = "A static call path exists from an explicitly supplied entrypoint; execution and exploitability are not established."
			f.Trace = trace
			if len(trace) > 0 {
				last := trace[len(trace)-1].Location
				f.Location = &last
			}
		}
		out = append(out, f)
	}
	for _, g := range gaps {
		if strings.Contains(g.ID, "analysis-incomplete") {
			out = append(out, g)
		}
	}
	return finding.New("reachability", out), nil
}
