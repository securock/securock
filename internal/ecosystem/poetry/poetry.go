package poetry

import (
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "poetry.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "poetry" }

func (Ecosystem) OSVEcosystem() string { return "PyPI" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock poetryLock
	if err := toml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		kind, registry := classify(pkg.Source)
		for _, file := range files(pkg) {
			dep := core.Dependency{
				Ecosystem:  "pypi",
				Resolver:   "poetry",
				Registry:   registry,
				SourceKind: kind,
				Name:       pkg.Name,
				Version:    pkg.Version,
				Filename:   file.Name,
				Digest:     core.NormalizeDigest(file.Hash),
			}
			if src := pkg.Source; src != nil {
				switch kind {
				case core.SourceGit:
					dep.Artifact = core.RemoteLocation(src.URL)
					dep.Resolved = src.ResolvedReference
					if dep.Resolved == "" {
						dep.Resolved = src.Reference
					}
				case core.SourceURL:
					dep.Artifact = core.RemoteLocation(src.URL)
				}
			}
			deps = append(deps, dep)
		}
	}
	core.ApplyPackageGraph(deps, packageKey, lock.graph(path))
	return deps, nil
}

func packageKey(dep core.Dependency) string {
	return core.NormalizePythonName(dep.Name) + "@" + dep.Version
}

type poetryLock struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name    string        `toml:"name"`
	Version string        `toml:"version"`
	Files   []poetryFile  `toml:"files"`
	Source  *poetrySource `toml:"source"`

	// Optional is true for a package only installed through an extra.
	Optional bool `toml:"optional"`
	// Poetry 2 records the groups that need a package; earlier versions recorded a
	// category; versions in between recorded neither.
	Groups       []string       `toml:"groups"`
	Category     string         `toml:"category"`
	Dependencies map[string]any `toml:"dependencies"`
}

type poetryFile struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

type poetrySource struct {
	Type              string `toml:"type"`
	URL               string `toml:"url"`
	Reference         string `toml:"reference"`
	ResolvedReference string `toml:"resolved_reference"`
}

type hashedFile struct {
	Name string
	Hash string
}

func files(pkg poetryPackage) []hashedFile {
	var out []hashedFile
	for _, file := range pkg.Files {
		if file.Hash == "" && file.File == "" {
			continue
		}
		out = append(out, hashedFile{Name: file.File, Hash: file.Hash})
	}
	if len(out) == 0 {
		return []hashedFile{{}}
	}
	return out
}

func classify(src *poetrySource) (kind, registry string) {
	if src == nil || src.Type == "" || src.Type == "pypi" || src.Type == "legacy" {
		registry = "https://pypi.org"
		if src != nil && src.URL != "" {
			if origin := network.Origin(src.URL); origin != "" {
				registry = origin
			} else {
				registry = strings.TrimRight(src.URL, "/")
			}
		}
		return core.SourceRegistry, registry
	}
	switch src.Type {
	case "git":
		return core.SourceGit, ""
	case "directory", "file":
		return core.SourceFile, ""
	case "url":
		return core.SourceURL, ""
	default:
		return core.SourceURL, ""
	}
}

// graph reads edges from the lockfile and scopes from the groups it records, falling back
// to the direct dependencies in pyproject.toml when the lockfile predates groups.
func (l poetryLock) graph(project string) core.PackageGraph {
	g := core.PackageGraph{
		Edges: map[string][]string{},
		Roots: map[string]string{},
		Fixed: map[string]string{},
	}
	byName := map[string][]string{}
	for _, pkg := range l.Package {
		if pkg.Name != "" && pkg.Version != "" {
			name := core.NormalizePythonName(pkg.Name)
			byName[name] = append(byName[name], name+"@"+pkg.Version)
		}
	}

	for _, pkg := range l.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		key := core.NormalizePythonName(pkg.Name) + "@" + pkg.Version
		for name := range pkg.Dependencies {
			g.Edges[key] = append(g.Edges[key], byName[core.NormalizePythonName(name)]...)
		}
		if scope := pkg.scope(); scope != "" {
			g.Fixed[key] = scope
		}
	}

	for scope, names := range projectDependencies(project) {
		for _, name := range names {
			for _, key := range byName[name] {
				g.Roots[key] = core.MergeScope(g.Roots[key], scope)
			}
		}
	}
	return g
}

// scope is what the lockfile itself says about a package, or "" when it says nothing.
func (p poetryPackage) scope() string {
	switch {
	case len(p.Groups) > 0:
		if slices.Contains(p.Groups, "main") {
			return core.ScopeRuntime
		}
		return core.ScopeDev
	case p.Category == "main":
		return core.ScopeRuntime
	case p.Category == "dev":
		return core.ScopeDev
	case p.Optional:
		return core.ScopeOptional
	}
	return ""
}
