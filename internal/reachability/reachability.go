// Package reachability decides whether a vulnerable package is part of what runs in
// production, using the scope and dependency edges recorded from the language lockfile.
//
// It works on the dependency graph, not on the code: it cannot tell whether a vulnerable
// function is called. Its one firm conclusion is "no", for packages the lockfile itself
// says are development-only and that no runtime package depends on.
package reachability

import (
	"sort"

	"github.com/securock/securock/pkg/lockfile"
)

// Annotate sets Reachable and Via on every checked vulnerability in the document.
//
//   - yes: a runtime package is, or depends on, the vulnerable package. Via holds the
//     shortest dependency path from a runtime package when the vulnerable one is indirect.
//   - no: the lockfile marks the package development-only and no runtime package reaches it.
//   - unknown: anything else, including lockfiles that record neither scope nor edges.
//     Reachability is never guessed: absence of information is not evidence of safety.
func Annotate(doc *lockfile.Document) {
	paths := runtimePaths(doc.Artifacts)
	for i := range doc.Artifacts {
		art := &doc.Artifacts[i]
		if art.Evidence.Vulnerabilities.State != lockfile.VulnChecked {
			continue
		}
		reach, via := classify(*art, paths)
		for j := range art.Evidence.Vulnerabilities.Items {
			item := &art.Evidence.Vulnerabilities.Items[j]
			item.Reachable = reach
			item.Via = via
		}
	}
}

func classify(art lockfile.Artifact, paths map[string][]string) (lockfile.Reachability, []string) {
	if path, ok := paths[art.ArtifactID()]; ok {
		if len(path) > 1 {
			return lockfile.ReachYes, path
		}
		return lockfile.ReachYes, nil
	}
	if art.Scope == lockfile.ScopeDev {
		return lockfile.ReachNo, nil
	}
	return lockfile.ReachUnknown, nil
}

// runtimePaths walks the graph breadth-first from the top of the runtime packages and
// returns the shortest path to each package it reaches. The top is every runtime package
// that no other runtime package depends on, which for most lockfiles is exactly the
// project's direct dependencies, so a path reads as "why is this here". Order is fixed so
// the result is deterministic.
func runtimePaths(arts []lockfile.Artifact) map[string][]string {
	deps := make(map[string][]string, len(arts))
	runtime := map[string]bool{}
	for _, a := range arts {
		id := a.ArtifactID()
		next := append([]string(nil), a.Dependencies...)
		sort.Strings(next)
		deps[id] = next
		if a.Scope == lockfile.ScopeRuntime {
			runtime[id] = true
		}
	}
	ids := make([]string, 0, len(runtime))
	for id := range runtime {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	needed := map[string]bool{}
	for _, id := range ids {
		for _, next := range deps[id] {
			if runtime[next] && next != id {
				needed[next] = true
			}
		}
	}

	paths := make(map[string][]string, len(ids))
	var queue []string
	walk := func() {
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			for _, next := range deps[id] {
				if _, seen := paths[next]; seen {
					continue
				}
				if _, known := deps[next]; !known {
					continue
				}
				paths[next] = append(append([]string(nil), paths[id]...), next)
				queue = append(queue, next)
			}
		}
	}
	start := func(id string) {
		paths[id] = []string{id}
		queue = append(queue, id)
	}

	for _, id := range ids {
		if !needed[id] {
			start(id)
		}
	}
	walk()
	// Runtime packages that only depend on each other form a cycle with no top; they are
	// still runtime packages, so each becomes its own start.
	for _, id := range ids {
		if _, seen := paths[id]; !seen {
			start(id)
			walk()
		}
	}
	return paths
}
