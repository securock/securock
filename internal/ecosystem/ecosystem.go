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

	seen := make(map[string]struct{})
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
			key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			deps = append(deps, dep)
		}
	}

	return deps, nil
}
