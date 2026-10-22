package core

import (
	"regexp"
	"sort"
	"strings"
)

// spread gives every node the strongest scope of any root that reaches it along edges.
// Nodes that are not in known are ignored, so edges to packages the lockfile does not
// contain (an uninstalled optional dependency) cost nothing.
func spread(roots map[string]string, edges func(string) []string, known func(string) bool) map[string]string {
	reached := make(map[string]string, len(roots))
	var queue []string
	push := func(id, scope string) {
		if !known(id) || scopeRank[scope] <= scopeRank[reached[id]] {
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
		for _, next := range edges(id) {
			push(next, reached[id])
		}
	}
	return reached
}

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
	reached := spread(roots,
		func(id string) []string { return deps[index[id]].DependsOn },
		func(id string) bool { _, ok := index[id]; return ok },
	)
	for id, scope := range reached {
		dep := &deps[index[id]]
		dep.Scope = MergeScope(dep.Scope, scope)
	}
}

// PackageGraph describes a lockfile in which one package yields several artifacts, such as
// a Python package with a source archive and many wheels.
type PackageGraph struct {
	// Edges maps a package key to the keys of the packages it depends on.
	Edges map[string][]string
	// Roots maps a package key to the scope the project declares it with.
	Roots map[string]string
	// Fixed maps a package key to a scope the lockfile states for the package itself.
	Fixed map[string]string
}

// ApplyPackageGraph works out scopes on packages and gives the result to every artifact of
// each package. Edges are recorded once per package, from its first artifact to the first
// artifact of each dependency, so a package with fifty wheels does not list fifty copies.
func ApplyPackageGraph(deps []Dependency, pkgOf func(Dependency) string, g PackageGraph) {
	first := make(map[string]int, len(deps))
	for i, dep := range deps {
		key := pkgOf(dep)
		if _, ok := first[key]; !ok {
			first[key] = i
		}
	}

	reached := spread(g.Roots,
		func(key string) []string { return g.Edges[key] },
		func(key string) bool { _, ok := first[key]; return ok },
	)

	for i := range deps {
		key := pkgOf(deps[i])
		deps[i].Scope = MergeScope(deps[i].Scope, MergeScope(g.Fixed[key], reached[key]))
		if first[key] != i {
			continue
		}
		var edges []string
		for _, target := range g.Edges[key] {
			if at, ok := first[target]; ok && target != key {
				edges = append(edges, Identity(deps[at]))
			}
		}
		deps[i].DependsOn = UnionIdentities(deps[i].DependsOn, edges)
	}
}

var pyNameSeparators = regexp.MustCompile(`[-_.]+`)

// NormalizePythonName applies PEP 503 normalization, so "Jinja2", "jinja2" and "zope.interface"
// compare equal to their lockfile spellings.
func NormalizePythonName(name string) string {
	return pyNameSeparators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// PythonRequirementName extracts the project name from a requirement string such as
// "requests[security]>=2.0; python_version >= '3.8'".
func PythonRequirementName(req string) string {
	req = strings.TrimSpace(req)
	end := len(req)
	for i, r := range req {
		if strings.ContainsRune("[<>=!~;@ (,", r) {
			end = i
			break
		}
	}
	return NormalizePythonName(req[:end])
}
