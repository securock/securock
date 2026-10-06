package evidence

import (
	"context"

	"github.com/securock/securock/internal/ecosystem"
)

// Multi fans out Collect across collectors and merges records by key.
// Later collectors do not overwrite keys already set by earlier ones.
type Multi struct {
	Collectors []Collector
}

// NewDefault returns the built-in evidence collectors for supported
// ecosystems (npm family and PyPI).
func NewDefault() Collector {
	return &Multi{Collectors: []Collector{NewNPM(), NewPyPI()}}
}

func (m *Multi) Collect(ctx context.Context, deps []ecosystem.Dependency) (map[string]Record, error) {
	out := make(map[string]Record)
	if m == nil {
		return out, nil
	}
	for _, c := range m.Collectors {
		if c == nil {
			continue
		}
		got, err := c.Collect(ctx, deps)
		if err != nil {
			return nil, err
		}
		for k, rec := range got {
			if _, exists := out[k]; exists {
				continue
			}
			out[k] = rec
		}
	}
	return out, nil
}
