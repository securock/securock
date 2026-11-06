package julia_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/julia"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/Manifest.toml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Manifest.toml"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = julia.New().Dependencies(dir)
	})
}
