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

func Collect(path string) ([]Dependency, []string, error) {
	ecosystems := Detect(path)
	if len(ecosystems) == 0 {
		return nil, nil, fmt.Errorf("no supported lockfile found in %s", path)
	}

	seen := make(map[string]struct{})
	var deps []Dependency
	names := make([]string, 0, len(ecosystems))

	for _, e := range ecosystems {
		names = append(names, e.Name())
		got, err := e.Dependencies(path)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, dep := range got {
			if dep.Name == "" || dep.Version == "" {
				continue
			}
			key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			deps = append(deps, dep)
		}
	}

	return deps, names, nil
}
