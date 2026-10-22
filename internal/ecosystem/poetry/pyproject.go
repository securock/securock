package poetry

import (
	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
)

type pyproject struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// projectDependencies reads the packages the project asks for directly, by scope, from
// pyproject.toml. Names are normalized. A missing or unreadable file yields nothing.
func projectDependencies(project string) map[string][]string {
	raw, err := core.ReadFile(core.Join(project, "pyproject.toml"))
	if err != nil {
		return nil
	}
	var doc pyproject
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	out := map[string][]string{}
	add := func(scope string, names ...string) {
		for _, name := range names {
			if name = core.NormalizePythonName(name); name != "" && name != "python" {
				out[scope] = append(out[scope], name)
			}
		}
	}
	requirements := func(scope string, reqs []string) {
		for _, req := range reqs {
			add(scope, core.PythonRequirementName(req))
		}
	}

	requirements(core.ScopeRuntime, doc.Project.Dependencies)
	for _, reqs := range doc.Project.OptionalDependencies {
		requirements(core.ScopeOptional, reqs)
	}
	for _, group := range doc.DependencyGroups {
		for _, item := range group {
			// A group entry is a requirement string, or a table that includes another group.
			if req, ok := item.(string); ok {
				add(core.ScopeDev, core.PythonRequirementName(req))
			}
		}
	}

	poetry := doc.Tool.Poetry
	for name := range poetry.Dependencies {
		add(core.ScopeRuntime, name)
	}
	for name := range poetry.DevDependencies {
		add(core.ScopeDev, name)
	}
	for group, def := range poetry.Group {
		scope := core.ScopeDev
		if group == "main" {
			scope = core.ScopeRuntime
		}
		for name := range def.Dependencies {
			add(scope, name)
		}
	}
	return out
}
