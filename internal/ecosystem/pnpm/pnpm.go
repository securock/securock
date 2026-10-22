package pnpm

import (
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/npmrc"
	"gopkg.in/yaml.v3"
)

const lockfileName = "pnpm-lock.yaml"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pnpm" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock pnpmLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	index := map[string]int{}
	for key, pkg := range lock.Packages {
		name, version := parseKey(key)
		if name == "" || version == "" {
			continue
		}
		tarball := pkg.Resolution.Tarball
		kind := core.SourceRegistry
		if local(pkg) {
			kind = core.SourceFile
			if tarball == "" {
				tarball = "file:local"
			}
		}
		registry := npmrc.Registry(path, name, tarball)
		if kind != core.SourceRegistry {
			registry = ""
		}
		dep := core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "pnpm",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    version,
			Digest:     core.NormalizeDigest(pkg.Resolution.Integrity),
		}
		index[core.Identity(dep)] = len(deps)
		deps = append(deps, dep)
	}

	addEdges(deps, index, lock)
	core.ApplyScopes(deps, lock.roots(index))
	return deps, nil
}

type pnpmLock struct {
	Importers map[string]pnpmImporter `yaml:"importers"`
	// A lockfile for a single project, before importers, keeps its direct dependencies here.
	pnpmImporter `yaml:",inline"`
	Packages     map[string]pnpmPackage  `yaml:"packages"`
	Snapshots    map[string]pnpmSnapshot `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmSpec `yaml:"dependencies"`
	DevDependencies      map[string]pnpmSpec `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmSpec `yaml:"optionalDependencies"`
}

// pnpmSpec is a direct dependency. Current lockfiles write {specifier, version}; older
// ones write the version alone.
type pnpmSpec struct {
	Version string
}

func (s *pnpmSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		s.Version = n.Value
		return nil
	case yaml.MappingNode:
		var m struct {
			Version string `yaml:"version"`
		}
		if err := n.Decode(&m); err != nil {
			return err
		}
		s.Version = m.Version
		return nil
	}
	return nil
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
		Type      string `yaml:"type"`
	} `yaml:"resolution"`
	// Older lockfiles keep dependencies on the package; current ones use snapshots.
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// addEdges records what each package depends on. Peer-dependency variants of one package
// have separate snapshots; they are merged under the one artifact.
func addEdges(deps []core.Dependency, index map[string]int, lock pnpmLock) {
	add := func(key string, groups ...map[string]string) {
		name, version := parseKey(key)
		i, ok := index["npm:"+name+"@"+version]
		if !ok {
			return
		}
		var edges []string
		for _, group := range groups {
			for depName, ref := range group {
				if id, ok := referenced(depName, ref); ok {
					if _, installed := index[id]; installed {
						edges = append(edges, id)
					}
				}
			}
		}
		deps[i].DependsOn = core.UnionIdentities(deps[i].DependsOn, edges)
	}
	for key, pkg := range lock.Packages {
		add(key, pkg.Dependencies, pkg.OptionalDependencies)
	}
	for key, snap := range lock.Snapshots {
		add(key, snap.Dependencies, snap.OptionalDependencies)
	}
}

// referenced turns a dependency entry into an artifact identity. The value is normally a
// version, with an optional peer-dependency suffix; an alias names another package.
func referenced(name, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "("); i >= 0 {
		ref = ref[:i]
	}
	switch {
	case ref == "", strings.HasPrefix(ref, "link:"), strings.HasPrefix(ref, "file:"):
		return "", false
	case strings.HasPrefix(ref, "/") || strings.LastIndex(ref, "@") > 0:
		aliased, version := parseKey(ref)
		if aliased == "" || version == "" {
			return "", false
		}
		return "npm:" + aliased + "@" + version, true
	}
	return "npm:" + name + "@" + ref, true
}

// roots maps each direct dependency of the project (or of every workspace package) to the
// scope it was declared with.
func (l pnpmLock) roots(index map[string]int) map[string]string {
	roots := map[string]string{}
	add := func(group map[string]pnpmSpec, scope string) {
		for name, spec := range group {
			id, ok := referenced(name, spec.Version)
			if !ok {
				continue
			}
			if _, installed := index[id]; installed {
				roots[id] = core.MergeScope(roots[id], scope)
			}
		}
	}
	importers := []pnpmImporter{l.pnpmImporter}
	for _, imp := range l.Importers {
		importers = append(importers, imp)
	}
	for _, imp := range importers {
		add(imp.Dependencies, core.ScopeRuntime)
		add(imp.OptionalDependencies, core.ScopeOptional)
		add(imp.DevDependencies, core.ScopeDev)
	}
	return roots
}

func local(pkg pnpmPackage) bool {
	switch pkg.Resolution.Type {
	case "directory", "git", "file":
		return true
	}
	return false
}

func parseKey(key string) (name, version string) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", ""
	}

	i := strings.LastIndex(key, "@")
	if i <= 0 {
		return "", ""
	}
	return key[:i], key[i+1:]
}
