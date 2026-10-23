// Package sast finds vulnerabilities in a project's own source code: untrusted data
// that reaches a dangerous call (taint analysis, following calls across functions and
// files) and insecure API use. Analysis is offline and deterministic.
//
// Go is analyzed with go/parser and go/types, so callees are resolved by their real
// identity rather than by name. JavaScript, TypeScript, Python, Java, PHP and Ruby are
// parsed with tree-sitter, lowered to a small shared IR (ir.go) and analyzed by one
// engine (irtaint.go) driven by a per-language model (lang_*.go); callees there are
// resolved through imports and declared types. A file that cannot be parsed is
// reported as an analysis-incomplete finding instead of being silently skipped.
package sast

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/securock/securock/internal/finding"
)

const (
	maxFileBytes = 2 << 20
	maxRounds    = 8
)

// skipDirs are never descended into: dependencies, VCS data, and test fixtures that
// are intentionally vulnerable.
var skipDirs = map[string]bool{"vendor": true, "node_modules": true, "testdata": true}

type pkg struct {
	path  string
	dir   string
	files []*ast.File
	names []string
	info  *types.Info
	types *types.Package
	state int // 0 unchecked, 1 checking, 2 done
}

// Analyze scans the source under root and returns findings sorted by severity.
func Analyze(root string) ([]finding.Finding, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	fset := token.NewFileSet()
	var out []finding.Finding

	pkgs, mods, props, incomplete, err := load(fset, abs)
	if err != nil {
		return nil, err
	}
	out = append(out, incomplete...)

	imp := &splitImporter{
		fset:  fset,
		other: importer.ForCompiler(fset, "source", nil).(types.ImporterFrom),
		own:   map[string]*pkg{},
	}
	for _, p := range pkgs {
		imp.own[p.path] = p
	}
	for _, p := range pkgs {
		imp.check(p)
	}

	rel := func(pos token.Pos) string {
		r, err := filepath.Rel(abs, fset.Position(pos).Filename)
		if err != nil {
			return filepath.ToSlash(fset.Position(pos).Filename)
		}
		return filepath.ToSlash(r)
	}
	out = append(out, taint(fset, abs, pkgs, mods, props, rel)...)
	for _, p := range pkgs {
		out = append(out, astRules(fset, p, rel)...)
	}
	return finding.New("sast", dedupeSecrets(out)).Findings, nil
}

// taint runs the interprocedural analysis to a fixed point over function summaries.
// Findings are taken from the final round only, once every summary is complete.
func taint(fset *token.FileSet, root string, pkgs []*pkg, mods []*module, props map[string]string, rel func(token.Pos) string) []finding.Finding {
	type fn struct {
		decl *ast.FuncDecl
		name string
		pkg  *pkg
	}
	var fns []fn
	for _, p := range pkgs {
		for _, f := range p.files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if obj, ok := p.info.Defs[fd.Name].(*types.Func); ok {
					fns = append(fns, fn{fd, normalize(obj.FullName()), p})
				}
			}
		}
	}
	sh := &shared{
		declTypes: map[types.Object]ast.Expr{},
		sums:      map[string]*summary{},
		methods:   map[string][]impl{},
		globals:   map[types.Object]taintSet{},
		regexps:   map[types.Object]string{},
	}
	for _, p := range pkgs {
		collectRegexps(p.files, p.info, sh.regexps)
		collectDeclTypes(p, sh.declTypes)
	}
	for _, f := range fns {
		if f.decl.Recv == nil {
			continue
		}
		if obj, ok := f.pkg.info.Defs[f.decl.Name].(*types.Func); ok {
			if recv := obj.Type().(*types.Signature).Recv(); recv != nil {
				t := recv.Type()
				if _, isPtr := t.(*types.Pointer); !isPtr {
					t = types.NewPointer(t)
				}
				sh.methods[obj.Name()] = append(sh.methods[obj.Name()], impl{recv: t, key: f.name})
			}
		}
	}
	proj := newProject(mods)
	proj.props = props
	var found map[string]finding.Finding
	var failed []finding.Finding
	prev := ""
	for range maxRounds {
		found = map[string]finding.Finding{}
		for _, f := range fns {
			a := &analyzer{shared: sh, fset: fset, info: f.pkg.info, rel: rel, found: found}
			sum, ok := a.safely(f.decl, f.name)
			if !ok {
				// Never let a bug in the analyzer pass for a clean result.
				l := a.loc(f.decl.Pos())
				found["incomplete|"+l.File+"|"+f.name] = unanalyzed(root, filepath.Join(root, l.File), "analyzing "+f.name+" failed")
				continue
			}
			sh.sums[f.name] = sum
		}
		failed = failed[:0]
		base := &analyzer{shared: sh, fset: fset, rel: rel, found: found}
		for _, m := range mods {
			spec := frontends[m.lang].spec
			for _, path := range analyzeModule(sh, spec, proj, m, base) {
				failed = append(failed, unanalyzed(root, filepath.Join(root, path), "analyzing a function in it failed"))
			}
		}
		// Summaries and global taint only grow, so a round that changes neither is final.
		cur := sh.signature()
		if cur == prev {
			break
		}
		prev = cur
	}
	for _, f := range failed {
		found["incomplete|"+f.Subject+"|"+f.Detail] = f
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]finding.Finding, 0, len(keys))
	for _, k := range keys {
		out = append(out, found[k])
	}
	return out
}

func load(fset *token.FileSet, root string) ([]*pkg, []*module, map[string]string, []finding.Finding, error) {
	props := map[string]string{}
	modDir, modPath := findModule(root)
	var pkgs []*pkg
	var mods []*module
	var incomplete []finding.Finding

	// lowValue is set below directories such as build or tests: Go there is still
	// analyzed (it is checked in), other languages there are usually output or fixtures.
	var walk func(dir string, lowValue bool) error
	walk = func(dir string, lowValue bool) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		byPkg := map[string]*pkg{}
		for _, e := range entries {
			name := e.Name()
			full := filepath.Join(dir, name)
			if e.IsDir() {
				if skipDirs[name] || (strings.HasPrefix(name, ".") && name != ".github") || strings.HasPrefix(name, "_") {
					continue
				}
				if err := walk(full, lowValue || skippedDirs[name]); err != nil {
					return err
				}
				continue
			}
			if strings.HasSuffix(strings.ToLower(name), ".properties") {
				readProperties(full, props)
			}
			if !lowValue && !skippedFile(name) && !strings.HasSuffix(name, "_test.go") {
				incomplete = append(incomplete, scanSecrets(root, full, relPath(root, full), name)...)
			}
			if !lowValue && isTemplate(name) {
				incomplete = append(incomplete, scanTemplate(root, full, relPath(root, full))...)
				continue
			}
			if kind := iacKind(relPath(root, full), name); kind != "" && !lowValue {
				incomplete = append(incomplete, scanIaC(root, full, relPath(root, full), kind)...)
				continue
			}
			if _, other := extensions[strings.ToLower(filepath.Ext(name))]; other {
				if lowValue || skippedFile(name) || frontends[extensions[strings.ToLower(filepath.Ext(name))][1]] == nil {
					continue
				}
				m, bad := loadOther(fset, root, full)
				if bad != "" {
					incomplete = append(incomplete, unanalyzed(root, full, bad))
				}
				if m != nil {
					mods = append(mods, m)
				}
				continue
			}
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			if info, err := e.Info(); err != nil || info.Size() > maxFileBytes {
				incomplete = append(incomplete, unanalyzed(root, full, "file is larger than the analysis limit"))
				continue
			}
			f, err := parser.ParseFile(fset, full, nil, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				incomplete = append(incomplete, unanalyzed(root, full, "it does not parse"))
				continue
			}
			if ast.IsGenerated(f) {
				continue
			}
			p := byPkg[f.Name.Name]
			if p == nil {
				p = &pkg{dir: dir, path: importPath(modDir, modPath, dir, f.Name.Name)}
				byPkg[f.Name.Name] = p
			}
			p.files = append(p.files, f)
			p.names = append(p.names, full)
		}
		names := make([]string, 0, len(byPkg))
		for n := range byPkg {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			pkgs = append(pkgs, byPkg[n])
		}
		return nil
	}
	if err := walk(root, false); err != nil {
		return nil, nil, nil, nil, err
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].path < mods[j].path })
	return pkgs, mods, props, incomplete, nil
}

// unanalyzed is the fail-closed result for a file the analyzer could not read: the
// absence of findings in it must not be mistaken for a clean bill of health.
func unanalyzed(root, file, why string) finding.Finding {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		rel = file
	}
	rel = filepath.ToSlash(rel)
	return finding.Finding{
		ID:       "sast:analysis-incomplete",
		Severity: finding.SeverityInfo,
		Title:    "File was not analyzed",
		Detail:   rel + " was skipped because " + why + "; vulnerabilities in it are unknown, not absent",
		Subject:  rel,
		Location: &finding.Location{File: rel, Line: 1},
	}
}

func findModule(dir string) (modDir, modPath string) {
	for d := dir; ; d = filepath.Dir(d) {
		if b, err := os.ReadFile(filepath.Join(d, "go.mod")); err == nil {
			for line := range strings.SplitSeq(string(b), "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
					return d, strings.Trim(strings.TrimSpace(rest), `"`)
				}
			}
		}
		if filepath.Dir(d) == d {
			return "", ""
		}
	}
}

func importPath(modDir, modPath, dir, name string) string {
	if modDir == "" {
		return name
	}
	r, err := filepath.Rel(modDir, dir)
	if err != nil || r == "." {
		return modPath
	}
	return modPath + "/" + filepath.ToSlash(r)
}

// The standard library never changes during a run, and type-checking it from source is
// the slow part, so it is loaded once per process. Everything else (the project's own
// packages and its dependencies) is loaded per analysis so a result never leaks between
// projects.
var (
	stdMu       sync.Mutex
	stdImporter = sync.OnceValue(func() types.ImporterFrom {
		return importer.ForCompiler(token.NewFileSet(), "source", nil).(types.ImporterFrom)
	})
)

type splitImporter struct {
	fset  *token.FileSet
	other types.ImporterFrom
	own   map[string]*pkg
}

func isStd(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// modeled reports whether a third-party package is one the rules name. Only those are
// type-checked from source: every other module is stubbed, which keeps a run in seconds
// instead of minutes, and its calls are matched by import path with their arguments
// assumed to flow into the result.
func modeled(path string) bool {
	path = normalize(path + "/")
	for _, m := range modeledPackages {
		if strings.HasPrefix(path, m+"/") {
			return true
		}
	}
	return false
}

// dirImporter resolves imports relative to the package being checked.
type dirImporter struct {
	imp *splitImporter
	dir string
}

func (d dirImporter) Import(path string) (*types.Package, error) {
	switch {
	case isStd(path):
		stdMu.Lock()
		defer stdMu.Unlock()
		return stdImporter().ImportFrom(path, d.dir, 0)
	case d.imp.own[path] != nil:
		// The project's own packages are checked once, by us, so every reference to
		// one of their functions has the same identity.
		return d.imp.check(d.imp.own[path])
	case modeled(path):
		return d.imp.other.ImportFrom(path, d.dir, 0)
	}
	return nil, fmt.Errorf("%s is not loaded", path)
}

// check type-checks a package. Errors are expected (third-party modules that are not
// downloaded) and tolerated: the checker still fills in everything it could resolve,
// and unresolved callees fall back to their import path.
func (im *splitImporter) check(p *pkg) (*types.Package, error) {
	switch p.state {
	case 1:
		return nil, fmt.Errorf("import cycle through %s", p.path)
	case 2:
		return p.types, nil
	}
	p.state = 1
	p.info = &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Implicits:  map[ast.Node]types.Object{},
	}
	defer func() {
		_ = recover()
		p.state = 2
	}()
	conf := types.Config{
		Importer:    dirImporter{im, p.dir},
		Error:       func(error) {},
		FakeImportC: true,
	}
	p.types, _ = conf.Check(p.path, im.fset, p.files, p.info)
	return p.types, nil
}

// loadOther parses and lowers a non-Go source file. bad explains why part or all of the
// file could not be analyzed.
func loadOther(fset *token.FileSet, root, full string) (*module, string) {
	info, err := os.Stat(full)
	if err != nil || info.Size() > maxFileBytes {
		return nil, "file is larger than the analysis limit"
	}
	src, err := os.ReadFile(full)
	if err != nil {
		return nil, "it cannot be read"
	}
	rel, err := filepath.Rel(root, full)
	if err != nil {
		rel = full
	}
	m, hadError, err := parseFile(fset, full, filepath.ToSlash(rel), src)
	switch {
	case m == nil:
		return nil, "it does not parse"
	case hadError || err != nil:
		return m, "it has syntax errors; the parts that parsed were analyzed"
	}
	return m, ""
}

func relPath(root, full string) string {
	r, err := filepath.Rel(root, full)
	if err != nil {
		return full
	}
	return filepath.ToSlash(r)
}

// dedupeSecrets drops a pattern-matched credential when a typed Go or IaC rule already
// reported the same line, so one literal is one finding.
func dedupeSecrets(in []finding.Finding) []finding.Finding {
	typed := map[string]bool{}
	for _, f := range in {
		if (f.ID == "sast:go/hardcoded-secret" || f.ID == "sast:iac/hardcoded-secret") && f.Location != nil {
			typed[fmt.Sprintf("%s:%d", f.Location.File, f.Location.Line)] = true
		}
	}
	out := in[:0:0]
	for _, f := range in {
		if strings.HasPrefix(f.ID, "sast:secrets/") && f.Location != nil && typed[fmt.Sprintf("%s:%d", f.Location.File, f.Location.Line)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// collectDeclTypes records the written type of every parameter, result and declared
// variable.
func collectDeclTypes(p *pkg, into map[types.Object]ast.Expr) {
	add := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				if o := p.info.Defs[n]; o != nil {
					into[o] = f.Type
				}
			}
		}
	}
	for _, f := range p.files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncType:
				add(n.Params)
				add(n.Results)
			case *ast.FuncDecl:
				add(n.Recv)
			case *ast.ValueSpec:
				if n.Type != nil {
					for _, name := range n.Names {
						if o := p.info.Defs[name]; o != nil {
							into[o] = n.Type
						}
					}
				}
			}
			return true
		})
	}
}

// readProperties adds the key=value lines of a Java properties file. The first definition
// of a key wins, so a value read here is the one most likely to be in use.
func readProperties(path string, into map[string]string) {
	st, err := os.Stat(path)
	if err != nil || st.Size() > 256<<10 {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			k = strings.TrimSpace(k)
			if _, dup := into[k]; !dup {
				into[k] = strings.TrimSpace(v)
			}
		}
	}
}
