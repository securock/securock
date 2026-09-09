package composer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/composer"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/composer.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"packages":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "composer.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = composer.New().Dependencies(dir)
	})
}
