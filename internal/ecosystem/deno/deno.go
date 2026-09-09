package deno

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/npmrc"
)

const lockfileName = "deno.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "deno" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock denoLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	npmPkgs := lock.NPM
	jsrPkgs := lock.JSR
	if lock.Packages != nil {
		if len(npmPkgs) == 0 {
			npmPkgs = lock.Packages.NPM
		}
		if len(jsrPkgs) == 0 {
			jsrPkgs = lock.Packages.JSR
		}
	}

	var deps []core.Dependency
	for key, pkg := range npmPkgs {
		name, version := splitNameVersion(key)
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "deno",
			Registry:   npmrc.Registry(path, name, ""),
			SourceKind: core.SourceRegistry,
			Name:       name,
			Version:    version,
			Digest:     core.NormalizeDigest(pkg.Integrity),
		})
	}
	for key, pkg := range jsrPkgs {
		name, version := splitNameVersion(key)
		if name == "" || version == "" {
			continue
		}
		deps = append(deps, core.Dependency{
			Ecosystem:  "jsr",
			Resolver:   "deno",
			Registry:   "https://jsr.io",
			SourceKind: core.SourceRegistry,
			Name:       name,
			Version:    version,
			Digest:     core.NormalizeDigest(pkg.Integrity),
		})
	}
	for url, hash := range lock.Remote {
		if url == "" || hash == "" {
			continue
		}
		digest := core.NormalizeDigest(hash)
		version := strings.TrimPrefix(digest, "sha256:")
		version = strings.TrimPrefix(version, "sha512:")
		deps = append(deps, core.Dependency{
			Ecosystem:  "url",
			Resolver:   "deno",
			SourceKind: core.SourceURL,
			Name:       url,
			Version:    version,
			Digest:     digest,
		})
	}
	return deps, nil
}

type denoLock struct {
	NPM      map[string]denoPkg `json:"npm"`
	JSR      map[string]denoPkg `json:"jsr"`
	Remote   map[string]string  `json:"remote"`
	Packages *denoV3Packages    `json:"packages"`
}

type denoV3Packages struct {
	NPM map[string]denoPkg `json:"npm"`
	JSR map[string]denoPkg `json:"jsr"`
}

type denoPkg struct {
	Integrity string `json:"integrity"`
}

func splitNameVersion(key string) (name, version string) {
	key = strings.TrimPrefix(key, "npm:")
	key = strings.TrimPrefix(key, "jsr:")
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return "", ""
	}
	return key[:at], key[at+1:]
}
