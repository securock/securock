package golang_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/golang"
)

func FuzzDependencies(f *testing.F) {
	mod, err := os.ReadFile("testdata/go.mod")
	if err != nil {
		f.Fatal(err)
	}
	sum, err := os.ReadFile("testdata/go.sum")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(mod, sum)
	f.Fuzz(func(t *testing.T, mod, sum []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), mod, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = golang.New().Dependencies(dir)
	})
}
