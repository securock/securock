package golang_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/golang"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/go.sum")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = golang.New().Dependencies(dir)
	})
}
