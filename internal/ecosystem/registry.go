package ecosystem

import (
	"github.com/securock/securock/internal/ecosystem/bun"
	"github.com/securock/securock/internal/ecosystem/bundler"
	"github.com/securock/securock/internal/ecosystem/cargo"
	"github.com/securock/securock/internal/ecosystem/composer"
	"github.com/securock/securock/internal/ecosystem/deno"
	"github.com/securock/securock/internal/ecosystem/golang"
	"github.com/securock/securock/internal/ecosystem/mix"
	"github.com/securock/securock/internal/ecosystem/npm"
	"github.com/securock/securock/internal/ecosystem/nuget"
	"github.com/securock/securock/internal/ecosystem/pdm"
	"github.com/securock/securock/internal/ecosystem/pnpm"
	"github.com/securock/securock/internal/ecosystem/poetry"
	"github.com/securock/securock/internal/ecosystem/pub"
	"github.com/securock/securock/internal/ecosystem/pypi"
	"github.com/securock/securock/internal/ecosystem/swiftpm"
	"github.com/securock/securock/internal/ecosystem/yarn"
)

func All() []Ecosystem {
	return []Ecosystem{
		pnpm.New(),
		yarn.New(),
		bun.New(),
		npm.New(),
		deno.New(),
		cargo.New(),
		golang.New(),
		pypi.New(),
		poetry.New(),
		pdm.New(),
		composer.New(),
		bundler.New(),
		nuget.New(),
		swiftpm.New(),
		pub.New(),
		mix.New(),
	}
}

func Prefer(found []Ecosystem) []Ecosystem {
	found = preferFamily(found, []string{"pnpm", "yarn", "bun", "npm"})
	found = preferFamily(found, []string{"pypi", "poetry", "pdm"})
	return found
}

func preferFamily(found []Ecosystem, order []string) []Ecosystem {
	present := map[string]bool{}
	member := map[string]bool{}
	for _, name := range order {
		member[name] = true
	}
	for _, e := range found {
		present[e.Name()] = true
	}
	chosen := ""
	for _, name := range order {
		if present[name] {
			chosen = name
			break
		}
	}
	if chosen == "" {
		return found
	}
	out := make([]Ecosystem, 0, len(found))
	for _, e := range found {
		if member[e.Name()] && e.Name() != chosen {
			continue
		}
		out = append(out, e)
	}
	return out
}
