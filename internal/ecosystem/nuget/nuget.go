package nuget

import (
	"encoding/json"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
	"github.com/securock/securock/internal/nugetconfig"
)

const lockfileName = "packages.lock.json"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "nuget" }

func (Ecosystem) OSVEcosystem() string { return "NuGet" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock nugetLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	registry := ""
	if !nugetconfig.Overridden(path) {
		registry = network.Provenance("nuget", nugetconfig.Sources(path))
	}
	seen := map[string]int{}
	var deps []core.Dependency
	roots := map[string]string{}
	for _, framework := range lock.Dependencies {
		for name, pkg := range framework {
			if name == "" || pkg.Resolved == "" {
				continue
			}
			if strings.EqualFold(pkg.Type, "Project") {
				continue
			}
			key := name + "@" + pkg.Resolved
			id, ok := seen[key]
			if !ok {
				id = len(deps)
				seen[key] = id
				deps = append(deps, core.Dependency{
					Ecosystem:  "nuget",
					Resolver:   "nuget",
					Registry:   registry,
					SourceKind: core.SourceRegistry,
					Name:       name,
					Version:    pkg.Resolved,
					Digest:     nugetDigest(pkg.ContentHash),
				})
			}

			// Each framework resolves its own versions, so edges are looked up within it.
			var edges []string
			for depName := range pkg.Dependencies {
				if target, ok := framework[depName]; ok && target.Resolved != "" && !strings.EqualFold(target.Type, "Project") {
					edges = append(edges, "nuget:"+depName+"@"+target.Resolved)
				}
			}
			deps[id].DependsOn = core.UnionIdentities(deps[id].DependsOn, edges)

			// NuGet has no development scope in the lockfile: a package the project
			// references directly is part of what it ships.
			if strings.EqualFold(pkg.Type, "Direct") {
				roots[core.Identity(deps[id])] = core.ScopeRuntime
			}
		}
	}
	core.ApplyScopes(deps, roots)
	return deps, nil
}

type nugetLock struct {
	Dependencies map[string]map[string]nugetPackage `json:"dependencies"`
}

type nugetPackage struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"`
}

func nugetDigest(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ":") || strings.Contains(raw, "-") {
		return core.NormalizeDigest(raw)
	}
	return core.NormalizeDigest("sha512-" + raw)
}
