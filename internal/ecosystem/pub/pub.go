package pub

import (
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
	"gopkg.in/yaml.v3"
)

const lockfileName = "pubspec.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pub" }

func (Ecosystem) OSVEcosystem() string { return "Pub" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock pubLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	for name, pkg := range lock.Packages {
		if name == "" || pkg.Version == "" {
			continue
		}
		if pkg.Source == "sdk" {
			continue
		}
		kind, registry, digest := classify(pkg)
		dep := core.Dependency{
			Ecosystem:  "pub",
			Resolver:   "pub",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    pkg.Version,
			Digest:     core.NormalizeDigest(digest),
			Scope:      scope(pkg.Dependency),
		}
		if kind == core.SourceGit {
			desc := mapping(pkg.Description)
			dep.Artifact = core.RemoteLocation(desc["url"])
			dep.Resolved = desc["resolved-ref"]
			if dep.Resolved == "" {
				dep.Resolved = desc["ref"]
			}
		}
		deps = append(deps, dep)
	}
	return deps, nil
}

type pubLock struct {
	Packages map[string]pubPackage `yaml:"packages"`
}

type pubPackage struct {
	Source      string    `yaml:"source"`
	Version     string    `yaml:"version"`
	Description yaml.Node `yaml:"description"`
	// Dependency is "direct main", "direct dev", "direct overridden", or "transitive".
	Dependency string `yaml:"dependency"`
}

// scope reads how pub says the project depends on a package. pub records no edges and does
// not say whether a transitive package comes from main or dev dependencies, so only direct
// dependencies have a scope.
func scope(dependency string) string {
	switch dependency {
	case "direct main", "direct overridden":
		return core.ScopeRuntime
	case "direct dev":
		return core.ScopeDev
	}
	return ""
}

func classify(pkg pubPackage) (kind, registry, digest string) {
	desc := mapping(pkg.Description)
	switch pkg.Source {
	case "git":
		return core.SourceGit, "", ""
	case "path":
		return core.SourceFile, "", ""
	default:
		if sha, ok := desc["sha256"]; ok {
			digest = sha
		}
		if u, ok := desc["url"]; ok {
			if origin := network.Origin(u); origin != "" {
				registry = origin
			} else {
				registry = strings.TrimRight(u, "/")
			}
		}
		if registry == "" {
			registry = "https://pub.dev"
		}
		return core.SourceRegistry, registry, digest
	}
}

func mapping(n yaml.Node) map[string]string {
	out := map[string]string{}
	if n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1].Value
	}
	return out
}
