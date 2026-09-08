package npm

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "package-lock.json"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "npm" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock packageLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	if len(lock.Packages) > 0 {
		return fromPackages(lock.Packages), nil
	}
	return fromDependencies(lock.Dependencies), nil
}

type packageLock struct {
	Packages     map[string]lockPackage `json:"packages"`
	Dependencies map[string]v1Dep       `json:"dependencies"`
}

type lockPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

type v1Dep struct {
	Version      string           `json:"version"`
	Integrity    string           `json:"integrity"`
	Dependencies map[string]v1Dep `json:"dependencies"`
}

func fromPackages(packages map[string]lockPackage) []core.Dependency {
	var deps []core.Dependency
	for key, pkg := range packages {
		if key == "" {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = packageName(key)
		}
		if name == "" || pkg.Version == "" {
			continue
		}
		deps = append(deps, core.Dependency{
			Ecosystem: "npm",
			Resolver:  "npm",
			Registry:  "https://registry.npmjs.org",
			Name:      name,
			Version:   pkg.Version,
			Digest:    core.NormalizeDigest(pkg.Integrity),
		})
	}
	return deps
}

func fromDependencies(deps map[string]v1Dep) []core.Dependency {
	var out []core.Dependency
	var walk func(map[string]v1Dep)
	walk = func(tree map[string]v1Dep) {
		for name, dep := range tree {
			if name != "" && dep.Version != "" {
				out = append(out, core.Dependency{
					Ecosystem: "npm",
					Resolver:  "npm",
					Registry:  "https://registry.npmjs.org",
					Name:      name,
					Version:   dep.Version,
					Digest:    core.NormalizeDigest(dep.Integrity),
				})
			}
			if len(dep.Dependencies) > 0 {
				walk(dep.Dependencies)
			}
		}
	}
	walk(deps)
	return out
}

func packageName(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
}
