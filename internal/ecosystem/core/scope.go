package core

import "sort"

// ApplyScopes sets each dependency's Scope from the project's direct dependencies, for
// lockfiles that record which packages the project asks for and what each one depends on,
// but not a scope for every package.
//
// roots maps the Identity of a direct dependency to the scope it was declared with. A
// package gets the strongest scope of any root that reaches it through DependsOn, so a
// package needed at runtime stays a runtime package even if a dev tool also uses it.
// Packages no root reaches keep their existing scope, which is usually empty.
func ApplyScopes(deps []Dependency, roots map[string]string) {
	index := make(map[string]int, len(deps))
	for i, dep := range deps {
		index[Identity(dep)] = i
	}

	reached := make(map[string]string, len(deps))
	var queue []string
	push := func(id, scope string) {
		if _, ok := index[id]; !ok || scopeRank[scope] <= scopeRank[reached[id]] {
			return
		}
		reached[id] = scope
		queue = append(queue, id)
	}

	ids := make([]string, 0, len(roots))
	for id := range roots {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		push(id, roots[id])
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, next := range deps[index[id]].DependsOn {
			push(next, reached[id])
		}
	}

	for id, scope := range reached {
		dep := &deps[index[id]]
		dep.Scope = MergeScope(dep.Scope, scope)
	}
}
