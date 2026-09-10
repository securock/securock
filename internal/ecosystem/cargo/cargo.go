package cargo

import (
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
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		if pkg.Source == "" {
			continue
		}
		if !strings.HasPrefix(pkg.Source, "registry+") && !strings.HasPrefix(pkg.Source, "sparse+") {
			continue
		}
		registry := network.RegistryURL(pkg.Source)
		deps = append(deps, core.Dependency{
			Ecosystem: "cargo",
			Resolver:  "cargo",
			Registry:  registry,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Digest:    core.NormalizeDigest(pkg.Checksum),
		})
	}
	return deps, nil
}

type cargoLock struct {
	Package []struct {
		Name     string `toml:"name"`
		Version  string `toml:"version"`
		Source   string `toml:"source"`
		Checksum string `toml:"checksum"`
	} `toml:"package"`
}
