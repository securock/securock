package pypi

import (
	"os"
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
		registry := network.Origin(pkg.Source.Registry)
		if registry == "" && pkg.Source.Registry != "" {
			registry = strings.TrimRight(pkg.Source.Registry, "/")
		}
		for _, file := range files(pkg) {
			deps = append(deps, core.Dependency{
				Ecosystem: "pypi",
				Resolver:  "uv",
				Registry:  registry,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Filename:  file.Name,
				Digest:    core.NormalizeDigest(file.Hash),
			})
		}
	}
	return deps, nil
}

type uvLock struct {
	Package []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  struct {
		Registry string `toml:"registry"`
	} `toml:"source"`
	SDist *struct {
		URL  string `toml:"url"`
		Hash string `toml:"hash"`
	} `toml:"sdist"`
	Wheels []struct {
		URL  string `toml:"url"`
		Hash string `toml:"hash"`
	} `toml:"wheels"`
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
