package yarn_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/yarn"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/yarn.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	berry, err := os.ReadFile("testdata/berry/yarn.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(berry)
	f.Add([]byte("# yarn lockfile v1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = yarn.New().Dependencies(dir)
	})
}
