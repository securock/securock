package ecosystem

import (
	"fmt"

	"github.com/securock/securock/internal/ecosystem/core"
)

type Dependency = core.Dependency
type Ecosystem = core.Ecosystem

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

	seen := make(map[string]string)
	var deps []Dependency

	for _, e := range ecosystems {
		got, err := e.Dependencies(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, dep := range got {
			if dep.Name == "" || dep.Version == "" {
				continue
			}
			if dep.Ecosystem == "" {
				dep.Ecosystem = e.Name()
			}
			if dep.Resolver == "" {
				dep.Resolver = e.Name()
			}
			key := depKey(dep)
			if prev, ok := seen[key]; ok {
				if prev == dep.Digest {
					continue
				}
				return nil, fmt.Errorf("artifact conflict detected\n\n%s\n\n%s\n%s", key, prev, dep.Digest)
			}
			seen[key] = dep.Digest
			deps = append(deps, dep)
		}
	}

	return deps, nil
}

func depKey(dep Dependency) string {
	key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
	if dep.Filename != "" {
		return key + "#" + dep.Filename
	}
	return key
}
