package julia

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
)

// Julia reads JuliaManifest.toml when a project keeps one for a specific Julia version.
var lockfileNames = []string{"Manifest.toml", "JuliaManifest.toml"}

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "julia" }

func (Ecosystem) OSVEcosystem() string { return "Julia" }

func (Ecosystem) Detect(path string) bool {
	return lockfile(path) != ""
}

func lockfile(path string) string {
	for _, name := range lockfileNames {
		if core.FileExists(core.Join(path, name)) {
			return name
		}
	}
	return ""
}

type entry struct {
	name    string
	version string
	tree    string
	repoURL string
	repoRev string
	local   string
	deps    []string
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	name := lockfile(path)
	if name == "" {
		return nil, fmt.Errorf("julia: no manifest in %s", path)
	}
	raw, err := core.ReadFile(core.Join(path, name))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	// Format 2.0 nests packages under "deps"; the original layout has them at the top level.
	table := doc
	if nested, ok := doc["deps"].(map[string]any); ok {
		table = nested
	}

	var entries []entry
	for pkg, value := range table {
		list, ok := value.([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				entries = append(entries, read(pkg, m))
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].name != entries[j].name {
			return entries[i].name < entries[j].name
		}
		return entries[i].version < entries[j].version
	})

	var deps []core.Dependency
	needs := map[string][]string{}
	for _, e := range entries {
		// Standard libraries ship with Julia: nothing is fetched, so nothing to record.
		if e.tree == "" && e.repoURL == "" && e.local == "" {
			continue
		}
		// git-tree-sha1 is a git tree hash, not the digest of a downloaded archive, so it is
		// kept as the resolved reference and never as a digest. The manifest does not say
		// which registry served a package, so none is recorded and the source stays unproven.
		dep := core.Dependency{
			Ecosystem:  "julia",
			Resolver:   "julia",
			SourceKind: core.SourceRegistry,
			Name:       e.name,
			Version:    e.version,
			Resolved:   e.tree,
		}
		switch {
		case e.repoURL != "":
			dep.SourceKind = core.SourceGit
			dep.Artifact = core.RemoteLocation(e.repoURL)
			if dep.Version == "" {
				dep.Version = firstNonEmpty(e.repoRev, e.tree)
			}
		case e.local != "":
			dep.SourceKind = core.SourceFile
			if dep.Version == "" {
				dep.Version = "path"
			}
		}
		if dep.Version == "" {
			continue
		}
		deps = append(deps, dep)
		needs[e.name] = e.deps
	}

	applyGraph(path, deps, needs)
	return deps, nil
}

func read(name string, m map[string]any) entry {
	e := entry{
		name:    name,
		version: str(m["version"]),
		tree:    str(m["git-tree-sha1"]),
		repoURL: str(m["repo-url"]),
		repoRev: str(m["repo-rev"]),
		local:   str(m["path"]),
	}
	switch deps := m["deps"].(type) {
	case []any:
		for _, d := range deps {
			if s := str(d); s != "" {
				e.deps = append(e.deps, s)
			}
		}
	case map[string]any:
		for d := range deps {
			e.deps = append(e.deps, d)
		}
	}
	return e
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
