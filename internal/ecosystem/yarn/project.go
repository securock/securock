package yarn

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

type depGroup struct {
	scope string
	deps  map[string]string
}

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

// projectDependencies reads the dependencies the project asks for from package.json and
// from each workspace package, because yarn.lock does not say which are development-only.
// A missing or unreadable package.json yields nothing, leaving scopes unknown.
func projectDependencies(project string) []depGroup {
	root, ok := readPackageJSON(filepath.Join(project, "package.json"))
	if !ok {
		return nil
	}
	pkgs := []packageJSON{root}
	for _, pattern := range workspacePatterns(root.Workspaces) {
		matches, err := filepath.Glob(filepath.Join(project, filepath.FromSlash(pattern), "package.json"))
		if err != nil {
			continue
		}
		for _, match := range matches {
			if pkg, ok := readPackageJSON(match); ok {
				pkgs = append(pkgs, pkg)
			}
		}
	}

	var groups []depGroup
	for _, pkg := range pkgs {
		groups = append(groups,
			depGroup{core.ScopeRuntime, pkg.Dependencies},
			depGroup{core.ScopeOptional, pkg.OptionalDependencies},
			depGroup{core.ScopeDev, pkg.DevDependencies},
		)
	}
	return groups
}

func readPackageJSON(path string) (packageJSON, bool) {
	raw, err := core.ReadFile(path)
	if err != nil {
		return packageJSON{}, false
	}
	var pkg packageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return packageJSON{}, false
	}
	return pkg, true
}

// workspacePatterns reads "workspaces", which is either a list of globs or an object with
// a "packages" list. Negations and recursive globs are skipped: the result only decides
// which packages count as roots, and missing one leaves its scopes unknown, never wrong.
func workspacePatterns(raw json.RawMessage) []string {
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var obj struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil
		}
		list = obj.Packages
	}
	var out []string
	for _, p := range list {
		if strings.HasPrefix(p, "!") || strings.Contains(p, "**") {
			continue
		}
		out = append(out, p)
	}
	return out
}
