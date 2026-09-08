package pnpm_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/pnpm"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/pnpm-lock.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("lockfileVersion: '9.0'\npackages: {}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = pnpm.New().Dependencies(dir)
	})
}
