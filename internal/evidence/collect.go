package evidence

import (
	"context"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/pkg/lockfile"
)

type Record struct {
	Provenance lockfile.EvidenceState
	Signature  lockfile.EvidenceState
}

type Collector interface {
	Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]Record, error)
}

func Key(dep ecosystem.Dependency) string {
	return ecosystem.Identity(dep)
}
