package ecosystem

import (
	"github.com/securock/securock/internal/ecosystem/cargo"
	"github.com/securock/securock/internal/ecosystem/golang"
	"github.com/securock/securock/internal/ecosystem/npm"
	"github.com/securock/securock/internal/ecosystem/pnpm"
	"github.com/securock/securock/internal/ecosystem/pypi"
	"github.com/securock/securock/internal/ecosystem/yarn"
)

func All() []Ecosystem {
	return []Ecosystem{
		pnpm.New(),
		yarn.New(),
		npm.New(),
		cargo.New(),
		golang.New(),
		pypi.New(),
	}
}

func Prefer(found []Ecosystem) []Ecosystem {
	chosen := npmFamilyChoice(found)
	if chosen == "" {
		return found
	}
	out := make([]Ecosystem, 0, len(found))
	for _, e := range found {
		if npmFamily(e.Name()) && e.Name() != chosen {
			continue
		}
		out = append(out, e)
	}
	return out
}

func npmFamilyChoice(found []Ecosystem) string {
	present := map[string]bool{}
	for _, e := range found {
		present[e.Name()] = true
	}
	for _, name := range []string{"pnpm", "yarn", "npm"} {
		if present[name] {
			return name
		}
	}
	return ""
}

func npmFamily(name string) bool {
	switch name {
	case "npm", "pnpm", "yarn":
		return true
	default:
		return false
	}
}
