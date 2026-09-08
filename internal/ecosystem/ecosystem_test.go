package ecosystem_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/ecosystem/core"
)

func TestPreferPnpmOverNpm(t *testing.T) {
	found := []ecosystem.Ecosystem{
		fakeEco("pnpm"),
		fakeEco("npm"),
		fakeEco("go"),
	}
	got := ecosystem.Prefer(found)
	if len(got) != 2 {
		t.Fatalf("got %d ecosystems, want 2", len(got))
	}
	if got[0].Name() != "pnpm" || got[1].Name() != "go" {
		t.Fatalf("unexpected order: %v", names(got))
	}
}

type fakeEco string

func (f fakeEco) Name() string       { return string(f) }
func (fakeEco) OSVEcosystem() string { return "" }
func (fakeEco) Detect(string) bool   { return true }
func (fakeEco) Dependencies(string) ([]core.Dependency, error) {
	return nil, nil
}

func names(ecos []ecosystem.Ecosystem) []string {
	out := make([]string, 0, len(ecos))
	for _, e := range ecos {
		out = append(out, e.Name())
	}
	return out
}
