package pdm

import (
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "pdm.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pdm" }

func (Ecosystem) OSVEcosystem() string { return "PyPI" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock pdmLock
	if err := toml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		kind, registry := classify(pkg)
		for _, file := range files(pkg) {
			deps = append(deps, core.Dependency{
				Ecosystem:  "pypi",
				Resolver:   "pdm",
				Registry:   registry,
				SourceKind: kind,
				Name:       pkg.Name,
				Version:    pkg.Version,
				Filename:   file.Name,
				Digest:     core.NormalizeDigest(file.Hash),
			})
		}
	}
	return deps, nil
}

type pdmLock struct {
	Package []pdmPackage `toml:"package"`
}

type pdmPackage struct {
	Name     string    `toml:"name"`
	Version  string    `toml:"version"`
	Path     string    `toml:"path"`
	URL      string    `toml:"url"`
	Git      string    `toml:"git"`
	Revision string    `toml:"revision"`
	Files    []pdmFile `toml:"files"`
}

type pdmFile struct {
	File string `toml:"file"`
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
}

type hashedFile struct {
	Name string
	Hash string
}

func files(pkg pdmPackage) []hashedFile {
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

func classify(pkg pdmPackage) (kind, registry string) {
	switch {
	case pkg.Path != "":
		return core.SourceFile, ""
	case pkg.Git != "":
		return core.SourceGit, ""
	case pkg.URL != "":
		return core.SourceURL, ""
	default:
		return core.SourceRegistry, fileRegistry(pkg)
	}
}

func fileRegistry(pkg pdmPackage) string {
	var urls []string
	for _, file := range pkg.Files {
		if file.URL != "" {
			urls = append(urls, file.URL)
		}
	}
	return network.Provenance("pypi", urls)
}
