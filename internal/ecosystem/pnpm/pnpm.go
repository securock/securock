package pnpm

import (
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
	"gopkg.in/yaml.v3"
)

const lockfileName = "pnpm-lock.yaml"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pnpm" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock pnpmLock
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	var deps []core.Dependency
	for key, pkg := range lock.Packages {
		name, version := parseKey(key)
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, core.Dependency{
			Ecosystem: "npm",
			Resolver:  "pnpm",
			Registry:  network.Origin(pkg.Resolution.Tarball),
			Name:      name,
			Version:   version,
			Digest:    core.NormalizeDigest(pkg.Resolution.Integrity),
		})
	}
	return deps, nil
}

type pnpmLock struct {
	Packages map[string]pnpmPackage `yaml:"packages"`
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
	} `yaml:"resolution"`
}

func parseKey(key string) (name, version string) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", ""
	}

	i := strings.LastIndex(key, "@")
	if i <= 0 {
		return "", ""
	}
	return key[:i], key[i+1:]
}
