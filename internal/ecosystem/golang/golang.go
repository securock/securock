package golang

import (
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const (
	sumName = "go.sum"
	modName = "go.mod"
)

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "go" }

func (Ecosystem) OSVEcosystem() string { return "Go" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, sumName)) ||
		core.FileExists(core.Join(path, modName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, sumName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var deps []core.Dependency
	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		hash := fields[len(fields)-1]
		version := fields[len(fields)-2]
		name := strings.Join(fields[:len(fields)-2], " ")
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deps = append(deps, core.Dependency{
			Ecosystem: "go",
			Name:      name,
			Version:   version,
			Digest:    core.NormalizeDigest(hash),
		})
	}
	return deps, nil
}
