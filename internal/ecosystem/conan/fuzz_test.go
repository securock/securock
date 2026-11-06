package conan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/conan"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/conan.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "conan.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = conan.New().Dependencies(dir)
	})
}
