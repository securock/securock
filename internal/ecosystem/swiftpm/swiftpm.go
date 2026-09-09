package swiftpm

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "Package.resolved"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "swiftpm" }

func (Ecosystem) OSVEcosystem() string { return "SwiftURL" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock resolved
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	pins := lock.Pins
	if len(pins) == 0 && lock.Object != nil {
		pins = lock.Object.Pins
	}

	var deps []core.Dependency
	for _, pin := range pins {
		name := pin.Identity
		if name == "" {
			name = pin.Package
		}
		location := pin.Location
		if location == "" {
			location = pin.RepositoryURL
		}
		version := pin.State.Version
		if version == "" {
			version = pin.State.Revision
		}
		if name == "" || version == "" {
			continue
		}
		kind := core.SourceRegistry
		registry := location
		if strings.EqualFold(pin.Kind, "localSourceControl") {
			kind = core.SourceFile
			registry = ""
		}
		deps = append(deps, core.Dependency{
			Ecosystem:  "swift",
			Resolver:   "swiftpm",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    version,
			Digest:     core.NormalizeDigest(pin.State.Revision),
		})
	}
	return deps, nil
}

type resolved struct {
	Pins   []pin `json:"pins"`
	Object *struct {
		Pins []pin `json:"pins"`
	} `json:"object"`
}

type pin struct {
	Identity      string `json:"identity"`
	Package       string `json:"package"`
	Kind          string `json:"kind"`
	Location      string `json:"location"`
	RepositoryURL string `json:"repositoryURL"`
	State         struct {
		Revision string `json:"revision"`
		Version  string `json:"version"`
	} `json:"state"`
}
