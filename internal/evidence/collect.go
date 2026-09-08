package evidence

import (
	"context"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/pkg/lockfile"
)

type Collector interface {
	Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]lockfile.EvidenceState, error)
}

func Key(dep ecosystem.Dependency) string {
	return dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
}
