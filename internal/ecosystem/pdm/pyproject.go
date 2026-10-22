package pdm

import (
	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
)

// groupScopes maps each non-default group name to the scope it implies: groups under
// [project.optional-dependencies] are extras, and groups under [tool.pdm.dev-dependencies]
// or [dependency-groups] are for development. A group named in both counts as optional,
// since shipping an extra is the stronger claim.
func groupScopes(project string) map[string]string {
	raw, err := core.ReadFile(core.Join(project, "pyproject.toml"))
	if err != nil {
		return nil
	}
	var doc struct {
		Project struct {
			OptionalDependencies map[string]any `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string]any `toml:"dependency-groups"`
		Tool             struct {
			PDM struct {
				DevDependencies map[string]any `toml:"dev-dependencies"`
			} `toml:"pdm"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := map[string]string{}
	for group := range doc.DependencyGroups {
		out[group] = core.ScopeDev
	}
	for group := range doc.Tool.PDM.DevDependencies {
		out[group] = core.ScopeDev
	}
	for group := range doc.Project.OptionalDependencies {
		out[group] = core.ScopeOptional
	}
	return out
}
