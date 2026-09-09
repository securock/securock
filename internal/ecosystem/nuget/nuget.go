package nuget

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "packages.lock.json"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "nuget" }

func (Ecosystem) OSVEcosystem() string { return "NuGet" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock nugetLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var deps []core.Dependency
	for _, framework := range lock.Dependencies {
		for name, pkg := range framework {
			if name == "" || pkg.Resolved == "" {
				continue
			}
			if strings.EqualFold(pkg.Type, "Project") {
				continue
			}
			key := name + "@" + pkg.Resolved
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			deps = append(deps, core.Dependency{
				Ecosystem:  "nuget",
				Resolver:   "nuget",
				Registry:   "https://api.nuget.org",
				SourceKind: core.SourceRegistry,
				Name:       name,
				Version:    pkg.Resolved,
				Digest:     nugetDigest(pkg.ContentHash),
			})
		}
	}
	return deps, nil
}

type nugetLock struct {
	Dependencies map[string]map[string]nugetPackage `json:"dependencies"`
}

type nugetPackage struct {
	Type        string `json:"type"`
	Resolved    string `json:"resolved"`
	ContentHash string `json:"contentHash"`
}

func nugetDigest(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ":") || strings.Contains(raw, "-") {
		return core.NormalizeDigest(raw)
	}
	return core.NormalizeDigest("sha512-" + raw)
}
