package npm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/npm"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/package-lock.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"packages":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = npm.New().Dependencies(dir)
	})
}
