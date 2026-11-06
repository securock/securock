package cabal_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cabal"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/cabal.project.freeze")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("constraints: any.a ==1.0\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cabal.project.freeze"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = cabal.New().Dependencies(dir)
	})
}
