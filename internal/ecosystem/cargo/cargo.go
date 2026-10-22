package cargo

import (
	"net/url"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "Cargo.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "cargo" }

func (Ecosystem) OSVEcosystem() string { return "crates.io" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock cargoLock
	if err := toml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	var packages []cargoPackage
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" || pkg.Source == "" {
			continue
		}
		if dep, ok := cargoDep(pkg); ok {
			deps = append(deps, dep)
			packages = append(packages, pkg)
		}
	}
	applyGraph(path, deps, packages)
	return deps, nil
}

// applyGraph records edges from Cargo.lock and scopes from the direct dependencies
// declared in Cargo.toml, because Cargo.lock merges normal, build, and dev dependencies.
func applyGraph(project string, deps []core.Dependency, packages []cargoPackage) {
	byName := map[string][]string{}
	for _, dep := range deps {
		byName[dep.Name] = append(byName[dep.Name], core.Identity(dep))
	}
	index := map[string]int{}
	for i, dep := range deps {
		index[core.Identity(dep)] = i
	}
	for i, pkg := range packages {
		var edges []string
		for _, ref := range pkg.Dependencies {
			edges = append(edges, resolveRef(ref, byName)...)
		}
		deps[i].DependsOn = core.UnionIdentities(nil, edges)
	}

	roots := map[string]string{}
	for scope, names := range manifestDependencies(project) {
		for _, name := range names {
			for _, id := range byName[name] {
				roots[id] = core.MergeScope(roots[id], scope)
			}
		}
	}
	core.ApplyScopes(deps, roots)
}

// resolveRef finds the packages a Cargo.lock dependency entry names. An entry is
// "name", "name version", or "name version (source)"; the version is left out when the
// name is unique.
func resolveRef(ref string, byName map[string][]string) []string {
	fields := strings.Fields(ref)
	if len(fields) == 0 {
		return nil
	}
	if len(fields) >= 2 {
		id := "cargo:" + fields[0] + "@" + fields[1]
		if slices.Contains(byName[fields[0]], id) {
			return []string{id}
		}
		return nil
	}
	return byName[fields[0]]
}

func cargoDep(pkg cargoPackage) (core.Dependency, bool) {
	dep := core.Dependency{
		Ecosystem: "cargo",
		Resolver:  "cargo",
		Name:      pkg.Name,
		Version:   pkg.Version,
		Digest:    core.NormalizeDigest(pkg.Checksum),
	}
	switch {
	case strings.HasPrefix(pkg.Source, "registry+"), strings.HasPrefix(pkg.Source, "sparse+"):
		dep.SourceKind = core.SourceRegistry
		dep.Registry = network.RegistryURL(pkg.Source)
		return dep, true
	case strings.HasPrefix(pkg.Source, "git+"):
		dep.SourceKind = core.SourceGit
		dep.Artifact, dep.Resolved = gitSource(pkg.Source)
		return dep, true
	case strings.HasPrefix(pkg.Source, "path+"):
		dep.SourceKind = core.SourceFile
		return dep, true
	default:
		return core.Dependency{}, false
	}
}

func gitSource(raw string) (repo, rev string) {
	raw = strings.TrimPrefix(raw, "git+")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", ""
	}
	rev = u.Fragment
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return strings.TrimRight(u.String(), "/"), rev
}

type cargoLock struct {
	Package []cargoPackage `toml:"package"`
}

type cargoPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}
