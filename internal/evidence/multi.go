package evidence

import (
	"context"
	"sync"

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

	// The collectors talk to different registries, so they run together. Results are
	// merged in collector order afterwards, which keeps "earlier wins" and the reported
	// error independent of timing.
	got := make([]map[string]Record, len(m.Collectors))
	errs := make([]error, len(m.Collectors))
	var wg sync.WaitGroup
	for i, c := range m.Collectors {
		if c == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = c.Collect(ctx, deps)
		}()
	}
	wg.Wait()

	for i := range m.Collectors {
		if errs[i] != nil {
			return nil, errs[i]
		}
		for k, rec := range got[i] {
			if _, exists := out[k]; exists {
				continue
			}
			out[k] = rec
		}
	}
	return out, nil
}
