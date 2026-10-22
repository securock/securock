package cargo

import (
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
)

type manifest struct {
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	Target            map[string]struct {
		Dependencies      map[string]any `toml:"dependencies"`
		DevDependencies   map[string]any `toml:"dev-dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
	} `toml:"target"`
	Workspace struct {
		Members []string `toml:"members"`
	} `toml:"workspace"`
}

// manifestDependencies reads the packages the project depends on directly, by scope, from
// Cargo.toml and from each workspace member. Build dependencies run on the build machine and
// shape what ships, so they count as runtime. A missing manifest yields nothing, which
// leaves scopes unknown.
func manifestDependencies(project string) map[string][]string {
	root, ok := readManifest(filepath.Join(project, "Cargo.toml"))
	if !ok {
		return nil
	}
	manifests := []manifest{root}
	for _, pattern := range root.Workspace.Members {
		matches, err := filepath.Glob(filepath.Join(project, filepath.FromSlash(pattern), "Cargo.toml"))
		if err != nil {
			continue
		}
		for _, match := range matches {
			if m, ok := readManifest(match); ok {
				manifests = append(manifests, m)
			}
		}
	}

	out := map[string][]string{}
	add := func(scope string, group map[string]any) {
		for key, value := range group {
			out[scope] = append(out[scope], crateName(key, value))
		}
	}
	for _, m := range manifests {
		add(core.ScopeRuntime, m.Dependencies)
		add(core.ScopeRuntime, m.BuildDependencies)
		add(core.ScopeDev, m.DevDependencies)
		for _, target := range m.Target {
			add(core.ScopeRuntime, target.Dependencies)
			add(core.ScopeRuntime, target.BuildDependencies)
			add(core.ScopeDev, target.DevDependencies)
		}
	}
	return out
}

// crateName is the crate a dependency refers to: its table key, unless renamed with
// package = "...".
func crateName(key string, value any) string {
	if table, ok := value.(map[string]any); ok {
		if real, ok := table["package"].(string); ok && real != "" {
			return real
		}
	}
	return key
}

func readManifest(path string) (manifest, bool) {
	raw, err := core.ReadFile(path)
	if err != nil {
		return manifest{}, false
	}
	var m manifest
	if err := toml.Unmarshal(raw, &m); err != nil {
		return manifest{}, false
	}
	return m, true
}
