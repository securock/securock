package poetry

import (
	"os"
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
	raw, err := os.ReadFile(core.Join(path, lockfileName))
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
	return deps, nil
}

type poetryLock struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name    string        `toml:"name"`
	Version string        `toml:"version"`
	Files   []poetryFile  `toml:"files"`
	Source  *poetrySource `toml:"source"`
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
