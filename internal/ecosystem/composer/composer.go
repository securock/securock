package composer

import (
	"encoding/json"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "composer.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "composer" }

func (Ecosystem) OSVEcosystem() string { return "Packagist" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock composerLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	var all []composerPackage
	// Composer lists in packages-dev only what the project needs for development.
	scopes := map[string]string{}
	for _, pkg := range lock.Packages {
		scopes[pkg.Name] = core.ScopeRuntime
	}
	for _, pkg := range lock.PackagesDev {
		scopes[pkg.Name] = core.MergeScope(scopes[pkg.Name], core.ScopeDev)
	}
	for _, pkg := range append(lock.Packages, lock.PackagesDev...) {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		all = append(all, pkg)
		kind, registry := classify(pkg)
		dep := core.Dependency{
			Ecosystem:  "packagist",
			Resolver:   "composer",
			Registry:   registry,
			SourceKind: kind,
			Name:       pkg.Name,
			Version:    pkg.Version,
			Digest:     core.NormalizeDigest(pkg.Dist.Shasum),
			Scope:      scopes[pkg.Name],
		}
		if pkg.Dist.URL != "" {
			dep.Artifact = pkg.Dist.URL
		} else if kind == core.SourceGit {
			dep.Artifact = core.RemoteLocation(pkg.Source.URL)
		}
		if pkg.Source.Reference != "" {
			dep.Resolved = pkg.Source.Reference
		}
		deps = append(deps, dep)
	}

	byName := map[string][]string{}
	for _, dep := range deps {
		name := strings.ToLower(dep.Name)
		byName[name] = append(byName[name], core.Identity(dep))
	}
	for i, pkg := range all {
		var edges []string
		for name := range pkg.Require {
			edges = append(edges, byName[strings.ToLower(name)]...)
		}
		deps[i].DependsOn = core.UnionIdentities(nil, edges)
	}
	return deps, nil
}

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	NotificationURL string `json:"notification-url"`
	// Require also lists php, ext-* and lib-*, which are not packages and match nothing.
	Require map[string]string `json:"require"`
	Dist    struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Shasum string `json:"shasum"`
	} `json:"dist"`
	Source struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Reference string `json:"reference"`
	} `json:"source"`
}

func classify(pkg composerPackage) (kind, registry string) {
	if pkg.Dist.URL != "" || pkg.NotificationURL != "" {
		if pkg.NotificationURL != "" {
			registry = network.Provenance("packagist", []string{pkg.NotificationURL})
		}
		return core.SourceRegistry, registry
	}
	switch pkg.Source.Type {
	case "git", "svn", "hg":
		return core.SourceGit, ""
	case "path":
		return core.SourceFile, ""
	default:
		if pkg.Source.URL != "" {
			return core.SourceGit, ""
		}
		return core.SourceRegistry, ""
	}
}
