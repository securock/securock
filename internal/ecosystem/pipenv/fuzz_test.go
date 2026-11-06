package pipenv_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/pipenv"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/Pipfile.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = pipenv.New().Dependencies(dir)
	})
}
