package bun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/npmrc"
)

const (
	lockfileName = "bun.lock"
	legacyName   = "bun.lockb"
)

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "bun" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName)) || core.FileExists(core.Join(path, legacyName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	if !core.FileExists(core.Join(path, lockfileName)) {
		return nil, fmt.Errorf("bun.lockb is unsupported; migrate to bun.lock first")
	}
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}
	raw = stripJSONC(raw)

	var lock bunLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	seen := map[string]int{}
	byKey := map[string]int{}
	pending := map[string]map[string]string{}
	var deps []core.Dependency
	for _, key := range keys {
		pkg := parsePackage(lock.Packages[key])
		if pkg.name == "" || pkg.version == "" {
			continue
		}
		id := pkg.name + "@" + pkg.version
		at, ok := seen[id]
		if !ok {
			kind := classify(pkg.version, pkg.tarball)
			registry := ""
			if kind == core.SourceRegistry {
				registry = npmrc.Registry(path, pkg.name, pkg.tarball)
			}
			at = len(deps)
			seen[id] = at
			deps = append(deps, core.Dependency{
				Ecosystem:  "npm",
				Resolver:   "bun",
				Registry:   registry,
				SourceKind: kind,
				Name:       pkg.name,
				Version:    pkg.version,
				Digest:     core.NormalizeDigest(pkg.integrity),
			})
		}
		byKey[key] = at
		// Nested copies of one version each have their own dependencies; keep them all.
		for name, rng := range pkg.dependencies {
			if pending[key] == nil {
				pending[key] = map[string]string{}
			}
			pending[key][name] = rng
		}
	}

	for key, group := range pending {
		var edges []string
		for name := range group {
			if target, ok := resolve(byKey, key, name); ok {
				edges = append(edges, core.Identity(deps[target]))
			}
		}
		at := byKey[key]
		deps[at].DependsOn = core.UnionIdentities(deps[at].DependsOn, edges)
	}

	roots := map[string]string{}
	for workspace, ws := range lock.Workspaces {
		for scope, group := range map[string]map[string]string{
			core.ScopeRuntime:  mergeMaps(ws.Dependencies, ws.PeerDependencies),
			core.ScopeOptional: ws.OptionalDependencies,
			core.ScopeDev:      ws.DevDependencies,
		} {
			for name := range group {
				target, ok := byKey[workspace+"/"+name]
				if !ok {
					target, ok = byKey[name]
				}
				if ok {
					id := core.Identity(deps[target])
					roots[id] = core.MergeScope(roots[id], scope)
				}
			}
		}
	}
	core.ApplyScopes(deps, roots)
	return deps, nil
}

type bunLock struct {
	Workspaces map[string]bunWorkspace    `json:"workspaces"`
	Packages   map[string]json.RawMessage `json:"packages"`
}

type bunWorkspace struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type bunPackage struct {
	name, version, tarball, integrity string
	dependencies                      map[string]string
}

func mergeMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// resolve finds the copy of name a package at key would load. Bun keys a nested copy as
// "parent/name", so the search starts under the package and walks outward.
func resolve(byKey map[string]int, from, name string) (int, bool) {
	path := splitKey(from)
	for {
		candidate := name
		if len(path) > 0 {
			candidate = strings.Join(path, "/") + "/" + name
		}
		if at, ok := byKey[candidate]; ok {
			return at, true
		}
		if len(path) == 0 {
			return 0, false
		}
		path = path[:len(path)-1]
	}
}

// splitKey splits a nested key into package names; a scope and its name stay together.
func splitKey(key string) []string {
	parts := strings.Split(key, "/")
	var out []string
	for i := 0; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			out = append(out, parts[i]+"/"+parts[i+1])
			i++
			continue
		}
		out = append(out, parts[i])
	}
	return out
}

func parsePackage(raw json.RawMessage) bunPackage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return bunPackage{}
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return bunPackage{}
		}
		name, version := splitLocator(s)
		return bunPackage{name: name, version: version}
	}
	var parts []json.RawMessage
	if json.Unmarshal(raw, &parts) != nil || len(parts) == 0 {
		return bunPackage{}
	}
	var locator string
	if json.Unmarshal(parts[0], &locator) != nil {
		return bunPackage{}
	}
	var pkg bunPackage
	pkg.name, pkg.version = splitLocator(locator)
	for _, part := range parts[1:] {
		var meta struct {
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		}
		if json.Unmarshal(part, &meta) == nil && (meta.Dependencies != nil || meta.OptionalDependencies != nil || meta.PeerDependencies != nil) {
			pkg.dependencies = mergeMaps(meta.Dependencies, meta.OptionalDependencies, meta.PeerDependencies)
			continue
		}
		var s string
		if json.Unmarshal(part, &s) != nil {
			continue
		}
		switch {
		case strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"):
			pkg.tarball = s
		case strings.HasPrefix(s, "sha256-") || strings.HasPrefix(s, "sha512-") || strings.HasPrefix(s, "sha1-") || strings.HasPrefix(s, "sha256:") || strings.HasPrefix(s, "sha512:"):
			pkg.integrity = s
		}
	}
	return pkg
}

func splitLocator(locator string) (name, version string) {
	locator = strings.TrimSpace(locator)
	at := strings.LastIndex(locator, "@")
	if at <= 0 {
		return locator, ""
	}
	return locator[:at], locator[at+1:]
}

func classify(version, tarball string) string {
	switch {
	case strings.HasPrefix(version, "workspace:"):
		return core.SourceWorkspace
	case strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "link:"):
		return core.SourceFile
	case strings.HasPrefix(version, "git") || strings.HasPrefix(version, "github:") || strings.HasPrefix(version, "gitlab:"):
		return core.SourceGit
	case strings.HasPrefix(tarball, "https://") || strings.HasPrefix(tarball, "http://"):
		return core.SourceRegistry
	case strings.Contains(version, ":"):
		return core.SourceURL
	default:
		return core.SourceRegistry
	}
}

func stripJSONC(raw []byte) []byte {
	var out bytes.Buffer
	inString := false
	escape := false
	for i := 0; i < len(raw); {
		c := raw[i]
		if inString {
			out.WriteByte(c)
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				inString = false
			}
			i++
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(c)
			i++
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '*' {
			i += 2
			for i < len(raw) && !(raw[i] == '*' && i+1 < len(raw) && raw[i+1] == '/') {
				i++
			}
			if i+1 < len(raw) {
				i += 2
			}
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\n' || raw[j] == '\r') {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				i++
				continue
			}
		}
		out.WriteByte(c)
		i++
	}
	return out.Bytes()
}
