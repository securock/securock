package cargo_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cargo"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/Cargo.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("version = 3\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = cargo.New().Dependencies(dir)
	})
}
