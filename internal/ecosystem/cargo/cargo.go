package cargo

import (
	"net/url"
	"os"
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
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock cargoLock
	if err := toml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" || pkg.Source == "" {
			continue
		}
		if dep, ok := cargoDep(pkg); ok {
			deps = append(deps, dep)
		}
	}
	return deps, nil
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
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Source   string `toml:"source"`
	Checksum string `toml:"checksum"`
}
