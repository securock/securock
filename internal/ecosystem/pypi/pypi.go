package pypi

import (
	"path"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "uv.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pypi" }

func (Ecosystem) OSVEcosystem() string { return "PyPI" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock uvLock
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
				Resolver:   "uv",
				Registry:   registry,
				SourceKind: kind,
				Name:       pkg.Name,
				Version:    pkg.Version,
				Filename:   file.Name,
				Digest:     core.NormalizeDigest(file.Hash),
			}
			switch kind {
			case core.SourceGit:
				dep.Artifact = core.RemoteLocation(pkg.Source.Git)
				dep.Resolved = pkg.Source.Rev
				if dep.Resolved == "" {
					dep.Resolved = core.RemoteRevision(pkg.Source.Git)
				}
			case core.SourceURL:
				dep.Artifact = core.RemoteLocation(pkg.Source.URL)
			}
			deps = append(deps, dep)
		}
	}
	core.ApplyPackageGraph(deps, packageKey, lock.graph())
	return deps, nil
}

func packageKey(dep core.Dependency) string {
	return core.NormalizePythonName(dep.Name) + "@" + dep.Version
}

type uvLock struct {
	Package []uvPackage `toml:"package"`
}

// graph reads dependencies from the lockfile. The project itself, and any workspace
// member, appear as packages with a local source; what they declare is what the project
// asks for: dependencies are runtime, extras optional, and dependency groups development.
func (l uvLock) graph() core.PackageGraph {
	g := core.PackageGraph{Edges: map[string][]string{}, Roots: map[string]string{}}
	byName := map[string][]string{}
	for _, pkg := range l.Package {
		if pkg.Name != "" && pkg.Version != "" {
			name := core.NormalizePythonName(pkg.Name)
			byName[name] = append(byName[name], name+"@"+pkg.Version)
		}
	}
	resolve := func(dep uvDependency) []string {
		name := core.NormalizePythonName(dep.Name)
		if dep.Version != "" {
			return []string{name + "@" + dep.Version}
		}
		return byName[name]
	}

	for _, pkg := range l.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		key := core.NormalizePythonName(pkg.Name) + "@" + pkg.Version
		for _, dep := range pkg.Dependencies {
			g.Edges[key] = append(g.Edges[key], resolve(dep)...)
		}
		if !pkg.Source.local() {
			continue
		}
		for _, dep := range pkg.Dependencies {
			for _, target := range resolve(dep) {
				g.Roots[target] = core.MergeScope(g.Roots[target], core.ScopeRuntime)
			}
		}
		for _, group := range pkg.OptionalDependencies {
			for _, dep := range group {
				for _, target := range resolve(dep) {
					g.Roots[target] = core.MergeScope(g.Roots[target], core.ScopeOptional)
				}
			}
		}
		for _, group := range pkg.DevDependencies {
			for _, dep := range group {
				for _, target := range resolve(dep) {
					g.Roots[target] = core.MergeScope(g.Roots[target], core.ScopeDev)
				}
			}
		}
	}
	return g
}

type uvDependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type uvPackage struct {
	Name                 string                    `toml:"name"`
	Version              string                    `toml:"version"`
	Source               uvSource                  `toml:"source"`
	Dependencies         []uvDependency            `toml:"dependencies"`
	OptionalDependencies map[string][]uvDependency `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDependency `toml:"dev-dependencies"`
	SDist                *struct {
		URL  string `toml:"url"`
		Hash string `toml:"hash"`
	} `toml:"sdist"`
	Wheels []struct {
		URL  string `toml:"url"`
		Hash string `toml:"hash"`
	} `toml:"wheels"`
}

type uvSource struct {
	Registry  string `toml:"registry"`
	Git       string `toml:"git"`
	Rev       string `toml:"rev"`
	Path      string `toml:"path"`
	Directory string `toml:"directory"`
	Editable  string `toml:"editable"`
	URL       string `toml:"url"`
	Virtual   string `toml:"virtual"`
}

// local reports whether the package is the project itself or a workspace member.
func (s uvSource) local() bool {
	return s.Virtual != "" || s.Editable != ""
}

func classify(src uvSource) (kind, registry string) {
	switch {
	case src.Git != "":
		return core.SourceGit, ""
	case src.Path != "" || src.Directory != "" || src.Editable != "":
		return core.SourceFile, ""
	case src.URL != "":
		return core.SourceURL, ""
	case src.Registry != "":
		if origin := network.Origin(src.Registry); origin != "" {
			return core.SourceRegistry, origin
		}
		return core.SourceRegistry, strings.TrimRight(src.Registry, "/")
	default:
		return core.SourceRegistry, "https://pypi.org"
	}
}

type uvFile struct {
	Name string
	Hash string
}

func files(pkg uvPackage) []uvFile {
	var out []uvFile
	if pkg.SDist != nil && pkg.SDist.Hash != "" {
		out = append(out, uvFile{Name: filename(pkg.SDist.URL), Hash: pkg.SDist.Hash})
	}
	for _, wheel := range pkg.Wheels {
		if wheel.Hash == "" {
			continue
		}
		out = append(out, uvFile{Name: filename(wheel.URL), Hash: wheel.Hash})
	}
	if len(out) == 0 {
		return []uvFile{{}}
	}
	return out
}

func filename(raw string) string {
	if raw == "" {
		return ""
	}
	u := strings.TrimSpace(raw)
	if i := strings.Index(u, "?"); i >= 0 {
		u = u[:i]
	}
	return path.Base(u)
}
