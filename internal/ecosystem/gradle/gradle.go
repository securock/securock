package gradle

import (
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "gradle.lockfile"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "gradle" }

func (Ecosystem) OSVEcosystem() string { return "Maven" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var deps []core.Dependency
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coord, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name, version, ok := mavenCoord(coord)
		if !ok {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		deps = append(deps, core.Dependency{
			Ecosystem:  "maven",
			Resolver:   "gradle",
			SourceKind: core.SourceRegistry,
			Name:       name,
			Version:    version,
		})
	}
	return deps, nil
}

func mavenCoord(coord string) (name, version string, ok bool) {
	coord = strings.TrimSpace(coord)
	if coord == "" || coord == "empty" {
		return "", "", false
	}
	parts := strings.Split(coord, ":")
	if len(parts) < 3 {
		return "", "", false
	}
	name = parts[0] + ":" + parts[1]
	version = parts[2]
	if name == ":" || version == "" {
		return "", "", false
	}
	return name, version, true
}
