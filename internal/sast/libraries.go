package sast

import (
	"encoding/json"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/securock/securock/internal/finding"
)

// Third-party code that ships inside the repository is analyzed as well, so a
// helper in a vendored package is followed into the API it calls instead of
// being treated as unknown. Only sources already in the repository are read:
// nothing is downloaded and no host is contacted.
//
// The library code is analyzed on its own: its findings are not reported (a
// dependency is not the user's code), but its summaries are, so that a call
// from the project into a package behaves like a call into the project's own
// helper.

const (
	// maxLibraryFiles bounds how many third-party files are parsed.
	maxLibraryFiles = 800
	// maxLibraryBytes bounds how much third-party code is parsed.
	maxLibraryBytes = 4 << 20
	// maxLibraryFileBytes skips a single file that is too big to be source.
	maxLibraryFileBytes = 256 << 10
	// maxLibrarySteps bounds the analysis of the third-party code.
	maxLibrarySteps = 200_000
)

// libraryRootNames are the directories that hold installed packages rather
// than the project's own code.
var libraryRootNames = []string{
	"node_modules", "site-packages", "vendor", "vendored", "third_party", "thirdparty",
}

// librarySkipDirs are the directories inside a package that hold no source
// worth analyzing.
var librarySkipDirs = map[string]bool{
	"__pycache__": true, "tests": true, "test": true, "__tests__": true,
	"spec": true, "e2e": true, "docs": true, "doc": true, "examples": true,
	"example": true, "benchmarks": true, "fixtures": true, "locale": true,
}

// librarySet is the third-party code loaded for one scan.
type librarySet struct {
	// files maps the path of every loaded library file, relative to the scanned
	// root, to the logical import path it is known by.
	files map[string]string
	// modules are the logical paths of the loaded library modules.
	modules map[string]bool
	// entries are the entry points of JavaScript packages, by package name.
	entries map[string]string
	// missing are the library files that could not be parsed.
	missing []string
	// skipped is the number of library files left out by the size limits.
	skipped int
	// firstSkipped is the first file left out, named in the report.
	firstSkipped string
}

// isLibraryRoot reports whether a directory holds installed packages.
func isLibraryRoot(name string) bool {
	for _, n := range libraryRootNames {
		if name == n {
			return true
		}
	}
	return false
}

// findLibraryRoots lists the directories that hold installed packages. A
// package inside a package is not searched again: the outer one already
// covers it.
func findLibraryRoots(root string) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 8 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() == ".git" {
				continue
			}
			name := e.Name()
			if isLibraryRoot(name) {
				out = append(out, filepath.Join(dir, name))
				continue
			}
			walk(filepath.Join(dir, name), depth+1)
		}
	}
	walk(root, 0)
	sort.Strings(out)
	return out
}

// libraryFiles lists the files of a package that may hold source.
func libraryFiles(root string) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 12 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			full := filepath.Join(dir, name)
			if e.IsDir() {
				if librarySkipDirs[name] || isLibraryRoot(name) {
					continue
				}
				walk(full, depth+1)
				continue
			}
			if skippedFile(name) {
				continue
			}
			out = append(out, full)
		}
	}
	walk(root, 0)
	sort.Strings(out)
	return out
}

// looksMinified reports whether a file is a generated bundle rather than
// source: one long line, or very long lines throughout.
func looksMinified(src []byte) bool {
	lines := strings.Split(string(src), "\n")
	if len(lines) < 2 {
		return len(src) > 4096
	}
	long := 0
	for _, l := range lines {
		if len(l) > 500 {
			long++
		}
	}
	return long*20 > len(lines)
}

// loadLibraries parses the packages the project imports. Only the packages
// named by an import are read: a repository that ships a dependency tree far
// larger than what it uses is not analyzed in full. The amount of code is
// bounded as well: a repository that ships more third-party code than the
// limit is reported as partially analyzed instead of being silently trusted.
func loadLibraries(fset *token.FileSet, root string, roots []string, specs map[string]bool, langs map[string]bool, taken map[string]bool) (*librarySet, []*module, []finding.Finding) {
	set := &librarySet{files: map[string]string{}, modules: map[string]bool{}, entries: map[string]string{}}
	var mods []*module
	var findings []finding.Finding
	loaded := map[string]bool{}
	files := 0
	bytes := 0
	// A package may import another one; the packages it names are read too,
	// one level deep, so that a chain of helpers is followed.
	for round := 0; round < 2 && len(specs) > 0; round++ {
		next := map[string]bool{}
		for _, spec := range sortedKeys(specs) {
			for _, libRoot := range roots {
				if loaded[spec] {
					continue
				}
				loaded[spec] = true
				dir := filepath.Join(libRoot, filepath.FromSlash(spec))
				if info, err := os.Stat(dir); err == nil && info.IsDir() {
					if entry, ok := packageEntry(libRoot, dir); ok {
						set.entries[spec] = entry
					}
					for _, full := range libraryFiles(dir) {
						m, _ := loadLibraryFile(fset, root, libRoot, full, langs, taken, set, &files, &bytes)
						if m != nil {
							mods = append(mods, m)
							collectSpecs(m, next)
						}
					}
					continue
				}
				if strings.HasSuffix(spec, ".py") {
					continue
				}
				// A Python module shipped as a single file.
				full := filepath.Join(libRoot, filepath.FromSlash(spec)+".py")
				if _, err := os.Stat(full); err != nil {
					continue
				}
				m, _ := loadLibraryFile(fset, root, libRoot, full, langs, taken, set, &files, &bytes)
				if m != nil {
					mods = append(mods, m)
					collectSpecs(m, next)
				}
			}
		}
		specs = next
	}
	for _, rel := range set.missing {
		findings = append(findings, libraryUnanalyzed(rel, "it does not parse"))
	}
	if set.skipped > 0 {
		findings = append(findings, finding.Finding{
			ID:       "sast:analysis-incomplete",
			Severity: finding.SeverityInfo,
			Title:    "Third-party code was not analyzed",
			Detail: fmt.Sprintf("%d third-party files were left out because the analysis limit was reached; the behavior of those packages is unknown, not absent",
				set.skipped),
			Subject:  set.firstSkipped,
			Location: &finding.Location{File: set.firstSkipped, Line: 1},
		})
	}
	return set, mods, findings
}

// loadLibraryFile parses one third-party file into a module.
func loadLibraryFile(fset *token.FileSet, root, libRoot, full string, langs map[string]bool, taken map[string]bool, set *librarySet, files, bytes *int) (*module, bool) {
	ext := strings.ToLower(filepath.Ext(full))
	info, ok := extensions[ext]
	if !ok || frontends[info[1]] == nil || !langs[info[1]] {
		return nil, false
	}
	logical := relPath(libRoot, full)
	if logical == "" || set.modules[logical] || taken[logical] {
		// The project's own module of that name wins.
		return nil, false
	}
	st, err := os.Stat(full)
	if err != nil || st.Size() > maxLibraryFileBytes {
		return nil, false
	}
	if *files >= maxLibraryFiles || *bytes+int(st.Size()) > maxLibraryBytes {
		set.skipped++
		if set.firstSkipped == "" {
			set.firstSkipped = relPath(root, full)
		}
		return nil, false
	}
	src, err := os.ReadFile(full)
	if err != nil || looksMinified(src) {
		return nil, false
	}
	m, hadError, err := parseFile(fset, full, logical, src)
	if m == nil {
		set.missing = append(set.missing, relPath(root, full))
		return nil, false
	}
	m.lib = true
	set.files[relPath(root, full)] = logical
	set.modules[logical] = true
	*files++
	*bytes += len(src)
	if hadError || err != nil {
		set.missing = append(set.missing, relPath(root, full))
	}
	return m, true
}

// collectSpecs names the packages a module imports.
func collectSpecs(m *module, out map[string]bool) {
	for _, q := range m.imports {
		if top := topPackage(q); top != "" {
			out[top] = true
		}
	}
	for _, ref := range m.locals {
		if top := topPackage(ref.spec); top != "" {
			out[top] = true
		}
	}
}

// topPackage is the name of the package an import refers to.
func topPackage(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") {
		return ""
	}
	if i := strings.Index(spec, "."); i > 0 {
		return spec[:i]
	}
	return spec
}

// sortedKeys lists the keys of a set in a stable order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firstLibraryFile names a loaded library file, for a report about it.
func firstLibraryFile(set *librarySet) string {
	names := make([]string, 0, len(set.files))
	for rel := range set.files {
		names = append(names, rel)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// fileOf names the file a summary key belongs to, for a report about it.
func (set *librarySet) fileOf(key string) string {
	if i := strings.LastIndex(key, "#"); i > 0 {
		key = key[:i]
	}
	for rel, logical := range set.files {
		if logical == key {
			return rel
		}
	}
	return ""
}

// libraryUnanalyzed reports a third-party file that was not analyzed. The
// behavior of that package is unknown, not absent.
func libraryUnanalyzed(rel, why string) finding.Finding {
	return finding.Finding{
		ID:       "sast:analysis-incomplete",
		Severity: finding.SeverityInfo,
		Title:    "File was not analyzed",
		Detail:   rel + " is third-party code that " + why + "; the behavior of that package is unknown, not absent",
		Subject:  rel,
		Location: &finding.Location{File: rel, Line: 1},
	}
}

// packageEntry finds the file a JavaScript package is loaded from, as its
// package.json names it.
func packageEntry(libRoot, dir string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return "", false
	}
	main := jsonMain(data)
	if main == "" {
		return "", false
	}
	entry := relPath(libRoot, filepath.Join(dir, filepath.FromSlash(main)))
	if entry == "" {
		return "", false
	}
	return entry, true
}

// jsonMain reads the entry point of a JavaScript package from its package.json.
func jsonMain(data []byte) string {
	var pkg struct {
		Main   string `json:"main"`
		Module string `json:"module"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ""
	}
	if pkg.Main != "" {
		return pkg.Main
	}
	return pkg.Module
}
