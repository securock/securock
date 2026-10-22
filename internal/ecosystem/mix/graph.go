package mix

import (
	"path/filepath"
	"regexp"

	"github.com/securock/securock/internal/ecosystem/core"
)

// applyGraph records edges from the lockfile and scopes from the direct dependencies in
// mix.exs, which says which are limited to dev or test with only:. Without mix.exs nothing
// says what the project asks for directly, so scopes stay unknown.
func applyGraph(project string, deps []core.Dependency, needs map[string][]string) {
	ids := map[string]string{}
	for _, dep := range deps {
		ids[dep.Name] = core.Identity(dep)
	}
	for i, dep := range deps {
		var edges []string
		for _, name := range needs[dep.Name] {
			if id, ok := ids[name]; ok {
				edges = append(edges, id)
			}
		}
		deps[i].DependsOn = core.UnionIdentities(nil, edges)
	}

	roots := map[string]string{}
	for name, scope := range manifestDependencies(project) {
		if id, ok := ids[name]; ok {
			roots[id] = scope
		}
	}
	core.ApplyScopes(deps, roots)
}

// dependencyTuple matches {:name, ...options} in the deps list of a mix.exs.
var dependencyTuple = regexp.MustCompile(`\{\s*:(\w+)\s*,([^{}]*)\}`)

// onlyOption matches only: :test or only: [:dev, :test].
var onlyOption = regexp.MustCompile(`\bonly:\s*(\[[^\]]*\]|:\w+)`)

// manifestDependencies reads the direct dependencies from mix.exs and from each umbrella
// app. A dependency limited with only: to :dev and :test is development-only; any other
// form, including one this does not understand, is runtime.
func manifestDependencies(project string) map[string]string {
	files := []string{filepath.Join(project, "mix.exs")}
	if apps, err := filepath.Glob(filepath.Join(project, "apps", "*", "mix.exs")); err == nil {
		files = append(files, apps...)
	}

	out := map[string]string{}
	found := false
	for _, file := range files {
		raw, err := core.ReadFile(file)
		if err != nil {
			continue
		}
		found = true
		for _, m := range dependencyTuple.FindAllStringSubmatch(string(raw), -1) {
			scope := core.ScopeRuntime
			if only := onlyOption.FindStringSubmatch(m[2]); only != nil && developmentOnly(only[1]) {
				scope = core.ScopeDev
			}
			out[m[1]] = core.MergeScope(out[m[1]], scope)
		}
	}
	if !found {
		return nil
	}
	return out
}

func developmentOnly(atoms string) bool {
	names := regexp.MustCompile(`:(\w+)`).FindAllStringSubmatch(atoms, -1)
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if n[1] != "dev" && n[1] != "test" {
			return false
		}
	}
	return true
}
