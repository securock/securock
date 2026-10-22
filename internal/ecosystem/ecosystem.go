package ecosystem

import (
	"fmt"

	"github.com/securock/securock/internal/ecosystem/core"
)

type Dependency = core.Dependency
type Ecosystem = core.Ecosystem

func Identity(dep Dependency) string {
	return core.Identity(dep)
}

func Detect(path string) []Ecosystem {
	var found []Ecosystem
	for _, e := range All() {
		if e.Detect(path) {
			found = append(found, e)
		}
	}
	return Prefer(found)
}

func Collect(path string) ([]Dependency, error) {
	ecosystems := Detect(path)
	if len(ecosystems) == 0 {
		return nil, fmt.Errorf("no supported lockfile found in %s", path)
	}

	seen := make(map[string]int)
	var deps []Dependency

	for _, e := range ecosystems {
		got, err := e.Dependencies(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, dep := range got {
			if dep.Name == "" {
				continue
			}
			if dep.Version == "" && dep.Ecosystem != "url" {
				continue
			}
			if dep.Ecosystem == "" {
				dep.Ecosystem = e.Name()
			}
			if dep.Resolver == "" {
				dep.Resolver = e.Name()
			}
			key := depKey(dep)
			if i, ok := seen[key]; ok {
				prev := &deps[i]
				if prev.Digest != dep.Digest {
					return nil, fmt.Errorf("artifact conflict detected\n\n%s\n\n%s\n%s", key, prev.Digest, dep.Digest)
				}
				// The same artifact appears again, such as a nested copy: keep what both say.
				prev.Scope = core.MergeScope(prev.Scope, dep.Scope)
				prev.DependsOn = core.UnionIdentities(prev.DependsOn, dep.DependsOn)
				continue
			}
			seen[key] = len(deps)
			deps = append(deps, dep)
		}
	}

	return deps, nil
}

func depKey(dep Dependency) string {
	return core.Identity(dep)
}
