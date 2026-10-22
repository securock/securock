package npm

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/npmrc"
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
	raw, err := core.ReadFile(core.Join(path, lockfileName))
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
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Integrity    string            `json:"integrity"`
	Resolved     string            `json:"resolved"`
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	DevOptional  bool              `json:"devOptional"`
	Dependencies map[string]string `json:"dependencies"`
	// Optional and peer dependencies are installed when present, so they are edges too.
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type v1Dep struct {
	Version      string            `json:"version"`
	Integrity    string            `json:"integrity"`
	Resolved     string            `json:"resolved"`
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	Requires     map[string]string `json:"requires"`
	Dependencies map[string]v1Dep  `json:"dependencies"`
}

// scopeOf reads npm's own classification. The lockfile marks only the exceptions:
// a package with no flag is installed for production.
func scopeOf(dev, optional, devOptional bool) string {
	switch {
	case optional || devOptional:
		return core.ScopeOptional
	case dev:
		return core.ScopeDev
	default:
		return core.ScopeRuntime
	}
}

func fromPackages(packages map[string]lockPackage) []core.Dependency {
	// First pass: every installable entry, keyed by its path in the lockfile.
	byKey := make(map[string]core.Dependency, len(packages))
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
		kind, registry := classifyResolved(pkg.Resolved)
		byKey[key] = core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "npm",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    pkg.Version,
			Digest:     core.NormalizeDigest(pkg.Integrity),
			Scope:      scopeOf(pkg.Dev, pkg.Optional, pkg.DevOptional),
		}
	}

	// Second pass: edges, resolved the way node does, from the package's own directory
	// outward through the enclosing node_modules directories.
	deps := make([]core.Dependency, 0, len(byKey))
	for key, dep := range byKey {
		pkg := packages[key]
		var edges []string
		for _, group := range []map[string]string{pkg.Dependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
			for name := range group {
				if target, ok := resolveInstalled(byKey, key, name); ok {
					edges = append(edges, core.Identity(target))
				}
			}
		}
		dep.DependsOn = core.UnionIdentities(nil, edges)
		deps = append(deps, dep)
	}
	return deps
}

// resolveInstalled finds the copy of name that code at path from would load: the nearest
// node_modules/name walking up from the package's directory.
func resolveInstalled(byKey map[string]core.Dependency, from, name string) (core.Dependency, bool) {
	const marker = "node_modules/"
	dir := from
	for {
		candidate := marker + name
		if dir != "" {
			candidate = dir + "/" + marker + name
		}
		if dep, ok := byKey[candidate]; ok {
			return dep, true
		}
		if dir == "" {
			return core.Dependency{}, false
		}
		// Step out of the enclosing node_modules/<pkg>, or out of a workspace directory.
		if i := strings.LastIndex(dir, "/"+marker); i >= 0 {
			dir = dir[:i]
		} else {
			dir = ""
		}
	}
}

func fromDependencies(deps map[string]v1Dep) []core.Dependency {
	var out []core.Dependency
	var walk func(tree map[string]v1Dep, scope []map[string]v1Dep)
	walk = func(tree map[string]v1Dep, scope []map[string]v1Dep) {
		// scope holds the trees enclosing this one, nearest last, for resolving "requires".
		scope = append(slices.Clone(scope), tree)
		for name, dep := range tree {
			if name != "" && dep.Version != "" {
				kind, registry := classifyResolved(dep.Resolved)
				var edges []string
				for req := range dep.Requires {
					if target, ok := resolveV1(append(slices.Clone(scope), dep.Dependencies), req); ok {
						edges = append(edges, "npm:"+req+"@"+target.Version)
					}
				}
				out = append(out, core.Dependency{
					Ecosystem:  "npm",
					Resolver:   "npm",
					Registry:   registry,
					SourceKind: kind,
					Name:       name,
					Version:    dep.Version,
					Digest:     core.NormalizeDigest(dep.Integrity),
					Scope:      scopeOf(dep.Dev, dep.Optional, false),
					DependsOn:  core.UnionIdentities(nil, edges),
				})
			}
			if len(dep.Dependencies) > 0 {
				walk(dep.Dependencies, scope)
			}
		}
	}
	walk(deps, nil)
	return out
}

// resolveV1 looks name up from the innermost enclosing tree outward.
func resolveV1(scope []map[string]v1Dep, name string) (v1Dep, bool) {
	for i := len(scope) - 1; i >= 0; i-- {
		if dep, ok := scope[i][name]; ok && dep.Version != "" {
			return dep, true
		}
	}
	return v1Dep{}, false
}

func classifyResolved(resolved string) (kind, registry string) {
	resolved = strings.TrimSpace(resolved)
	switch {
	case resolved == "":
		return core.SourceWorkspace, ""
	case strings.HasPrefix(resolved, "file:") || strings.HasPrefix(resolved, "link:"):
		return core.SourceFile, ""
	case strings.HasPrefix(resolved, "git+") || strings.HasPrefix(resolved, "git://"):
		return core.SourceGit, ""
	case strings.HasPrefix(resolved, "https://") || strings.HasPrefix(resolved, "http://"):
		return core.SourceRegistry, npmrc.Registry(".", "", resolved)
	default:
		return core.SourceURL, ""
	}
}

func packageName(key string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(key, marker)
	if i < 0 {
		return ""
	}
	return key[i+len(marker):]
}
