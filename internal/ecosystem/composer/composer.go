package composer

import (
	"encoding/json"
	"os"

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
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock composerLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	for _, pkg := range append(lock.Packages, lock.PackagesDev...) {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		kind, registry := classify(pkg)
		dep := core.Dependency{
			Ecosystem:  "packagist",
			Resolver:   "composer",
			Registry:   registry,
			SourceKind: kind,
			Name:       pkg.Name,
			Version:    pkg.Version,
			Digest:     core.NormalizeDigest(pkg.Dist.Shasum),
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
	Dist            struct {
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
