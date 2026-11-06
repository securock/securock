package julia

import (
	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
)

// applyGraph records edges from the manifest and scopes from the direct dependencies in
// Project.toml. Without a Project.toml nothing says what the project asks for directly,
// so scopes stay unknown.
func applyGraph(project string, deps []core.Dependency, needs map[string][]string) {
	byName := map[string][]string{}
	for _, dep := range deps {
		byName[dep.Name] = append(byName[dep.Name], core.Identity(dep))
	}
	for i, dep := range deps {
		var edges []string
		for _, name := range needs[dep.Name] {
			edges = append(edges, byName[name]...)
		}
		deps[i].DependsOn = core.UnionIdentities(nil, edges)
	}

	roots := map[string]string{}
	for scope, names := range manifestDependencies(project) {
		for _, name := range names {
			for _, id := range byName[name] {
				roots[id] = core.MergeScope(roots[id], scope)
			}
		}
	}
	core.ApplyScopes(deps, roots)
}

// manifestDependencies reads the direct dependencies from Project.toml: [deps] is runtime,
// and packages that only appear in [extras] (test dependencies) are dev. A missing or
// unreadable file yields nothing.
func manifestDependencies(project string) map[string][]string {
	var raw []byte
	for _, name := range []string{"Project.toml", "JuliaProject.toml"} {
		if b, err := core.ReadFile(core.Join(project, name)); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		return nil
	}
	var doc struct {
		Deps   map[string]any `toml:"deps"`
		Extras map[string]any `toml:"extras"`
	}
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := map[string][]string{}
	for name := range doc.Deps {
		out[core.ScopeRuntime] = append(out[core.ScopeRuntime], name)
	}
	for name := range doc.Extras {
		if _, runtime := doc.Deps[name]; !runtime {
			out[core.ScopeDev] = append(out[core.ScopeDev], name)
		}
	}
	return out
}
