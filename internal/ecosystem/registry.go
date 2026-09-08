package ecosystem

import (
	"github.com/securock/securock/internal/ecosystem/cargo"
	"github.com/securock/securock/internal/ecosystem/golang"
	"github.com/securock/securock/internal/ecosystem/npm"
	"github.com/securock/securock/internal/ecosystem/pnpm"
	"github.com/securock/securock/internal/ecosystem/pypi"
)

func All() []Ecosystem {
	return []Ecosystem{
		pnpm.New(),
		npm.New(),
		cargo.New(),
		golang.New(),
		pypi.New(),
	}
}

func Prefer(found []Ecosystem) []Ecosystem {
	hasPnpm := false
	for _, e := range found {
		if e.Name() == "pnpm" {
			hasPnpm = true
			break
		}
	}
	if !hasPnpm {
		return found
	}

	out := make([]Ecosystem, 0, len(found))
	for _, e := range found {
		if e.Name() == "npm" {
			continue
		}
		out = append(out, e)
	}
	return out
}
