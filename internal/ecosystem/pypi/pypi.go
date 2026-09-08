package pypi

import (
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
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
	raw, err := os.ReadFile(core.Join(path, lockfileName))
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
		deps = append(deps, core.Dependency{
			Ecosystem: "pypi",
			Name:      pkg.Name,
			Version:   pkg.Version,
			Digest:    digest(pkg),
		})
	}
	return deps, nil
}

type uvLock struct {
	Package []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	SDist   *struct {
		Hash string `toml:"hash"`
	} `toml:"sdist"`
	Wheels []struct {
		Hash string `toml:"hash"`
	} `toml:"wheels"`
}

func digest(pkg uvPackage) string {
	if pkg.SDist != nil && pkg.SDist.Hash != "" {
		return core.NormalizeDigest(pkg.SDist.Hash)
	}
	if len(pkg.Wheels) > 0 {
		return core.NormalizeDigest(pkg.Wheels[0].Hash)
	}
	return ""
}
