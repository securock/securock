package poetry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/poetry"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/poetry.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("[[package]]\nname = \"x\"\nversion = \"1\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = poetry.New().Dependencies(dir)
	})
}
