package deno

import (
	"encoding/json"
	"fmt"
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
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock denoLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	if err := supportedVersion(lock.Version); err != nil {
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

	seen := map[string]struct{}{}
	var deps []core.Dependency
	// edges holds each package's declared dependencies until every package is known.
	edges := map[string][]string{}
	for key, pkg := range npmPkgs {
		name, version := splitNameVersion(key)
		if name == "" || version == "" {
			continue
		}
		id := "npm:" + name + "@" + version
		edges[id] = append(edges[id], pkg.Dependencies...)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		deps = append(deps, core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "deno",
			Registry:   npmRegistry(path, name),
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
		edges["jsr:"+name+"@"+version] = append(edges["jsr:"+name+"@"+version], pkg.Dependencies...)
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
	targets := map[string]struct{}{}
	for from, to := range lock.Redirects {
		if from == "" || to == "" {
			continue
		}
		targets[to] = struct{}{}
		dep := core.Dependency{
			Ecosystem:  "url",
			Resolver:   "deno",
			SourceKind: core.SourceURL,
			Name:       from,
			Requested:  from,
			Resolved:   to,
		}
		if hash := lock.Remote[to]; hash != "" {
			dep.Version, dep.Digest = remoteVersion(hash)
		}
		deps = append(deps, dep)
	}
	for url, hash := range lock.Remote {
		if url == "" || hash == "" {
			continue
		}
		if _, ok := targets[url]; ok {
			continue
		}
		version, digest := remoteVersion(hash)
		deps = append(deps, core.Dependency{
			Ecosystem:  "url",
			Resolver:   "deno",
			SourceKind: core.SourceURL,
			Name:       url,
			Version:    version,
			Digest:     digest,
		})
	}
	specifiers := lock.Specifiers
	if len(specifiers) == 0 && lock.Packages != nil {
		specifiers = lock.Packages.Specifiers
	}
	applyGraph(deps, edges, specifiers, lock.workspaceDependencies())
	return deps, nil
}

// applyGraph records each package's dependencies and marks the workspace's direct
// dependencies as runtime roots. Deno has no development-only dependencies, so every
// package a root reaches is a runtime package.
func applyGraph(deps []core.Dependency, edges map[string][]string, specifiers map[string]string, rootSpecs []string) {
	index := map[string]int{}
	byName := map[string][]string{}
	for i, dep := range deps {
		if dep.Ecosystem != "npm" && dep.Ecosystem != "jsr" {
			continue
		}
		id := core.Identity(dep)
		index[id] = i
		byName[dep.Ecosystem+":"+dep.Name] = append(byName[dep.Ecosystem+":"+dep.Name], id)
	}

	// resolveSpec turns "npm:react@19" or "jsr:@std/assert@1" into an artifact identity.
	resolveSpec := func(spec string) (string, bool) {
		version, ok := specifiers[spec]
		if !ok {
			return "", false
		}
		scheme, rest, _ := strings.Cut(spec, ":")
		name, _ := splitAtVersion(rest)
		if name == "" {
			name = rest
		}
		id := scheme + ":" + name + "@" + stripPeerContext(version)
		_, found := index[id]
		return id, found
	}

	for id, items := range edges {
		self, ok := index[id]
		if !ok {
			continue
		}
		scheme := strings.SplitN(id, ":", 2)[0]
		var out []string
		for _, item := range items {
			if strings.HasPrefix(item, "npm:") || strings.HasPrefix(item, "jsr:") {
				if target, ok := resolveSpec(item); ok {
					out = append(out, target)
				}
				continue
			}
			// An npm package lists its dependencies by name, or by name@version when
			// more than one version is locked.
			if name, version := splitNameVersion(item); name != "" && version != "" {
				if _, ok := index[scheme+":"+name+"@"+version]; ok {
					out = append(out, scheme+":"+name+"@"+version)
				}
				continue
			}
			if candidates := byName[scheme+":"+item]; len(candidates) == 1 {
				out = append(out, candidates[0])
			}
		}
		deps[self].DependsOn = core.UnionIdentities(deps[self].DependsOn, out)
	}

	roots := map[string]string{}
	for _, spec := range rootSpecs {
		if id, ok := resolveSpec(spec); ok {
			roots[id] = core.ScopeRuntime
		}
	}
	core.ApplyScopes(deps, roots)
}

func supportedVersion(v string) error {
	switch v {
	case "3", "4", "5":
		return nil
	case "":
		return fmt.Errorf("missing deno.lock version")
	default:
		return fmt.Errorf("unsupported deno.lock version %q", v)
	}
}

type denoLock struct {
	Version    string             `json:"version"`
	Specifiers map[string]string  `json:"specifiers"`
	NPM        map[string]denoPkg `json:"npm"`
	JSR        map[string]denoPkg `json:"jsr"`
	Remote     map[string]string  `json:"remote"`
	Redirects  map[string]string  `json:"redirects"`
	Packages   *denoV3Packages    `json:"packages"`
	Workspace  denoWorkspace      `json:"workspace"`
}

type denoV3Packages struct {
	Specifiers map[string]string  `json:"specifiers"`
	NPM        map[string]denoPkg `json:"npm"`
	JSR        map[string]denoPkg `json:"jsr"`
}

type denoPkg struct {
	Integrity    string   `json:"integrity"`
	Dependencies []string `json:"dependencies"`
}

// denoWorkspace lists what the project and its members import directly.
type denoWorkspace struct {
	Dependencies []string `json:"dependencies"`
	PackageJSON  struct {
		Dependencies []string `json:"dependencies"`
	} `json:"packageJson"`
	Members map[string]struct {
		Dependencies []string `json:"dependencies"`
		PackageJSON  struct {
			Dependencies []string `json:"dependencies"`
		} `json:"packageJson"`
	} `json:"members"`
}

func (l denoLock) workspaceDependencies() []string {
	w := l.Workspace
	out := append(append([]string(nil), w.Dependencies...), w.PackageJSON.Dependencies...)
	for _, member := range w.Members {
		out = append(out, member.Dependencies...)
		out = append(out, member.PackageJSON.Dependencies...)
	}
	return out
}

func splitNameVersion(key string) (name, version string) {
	key = strings.TrimPrefix(key, "npm:")
	key = strings.TrimPrefix(key, "jsr:")
	name, rest := splitAtVersion(key)
	if name == "" || rest == "" {
		return "", ""
	}
	return name, stripPeerContext(rest)
}

func splitAtVersion(key string) (name, rest string) {
	if strings.HasPrefix(key, "@") {
		slash := strings.IndexByte(key, '/')
		if slash < 1 {
			return "", ""
		}
		at := strings.IndexByte(key[slash+1:], '@')
		if at < 1 {
			return "", ""
		}
		at += slash + 1
		return key[:at], key[at+1:]
	}
	at := strings.IndexByte(key, '@')
	if at <= 0 {
		return "", ""
	}
	return key[:at], key[at+1:]
}

func stripPeerContext(version string) string {
	if base, _, ok := strings.Cut(version, "_"); ok {
		return base
	}
	return version
}

func npmRegistry(project, name string) string {
	registry := npmrc.Registry(project, name, "")
	if registry == "" {
		return npmrc.DefaultRegistry
	}
	return registry
}

func remoteVersion(hash string) (version, digest string) {
	digest = core.NormalizeDigest(hash)
	version = strings.TrimPrefix(digest, "sha256:")
	version = strings.TrimPrefix(version, "sha512:")
	return version, digest
}
