package swiftpm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/swiftpm"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/Package.resolved")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"pins":[],"version":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = swiftpm.New().Dependencies(dir)
	})
}
