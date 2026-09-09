package gradle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/gradle"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/gradle.lockfile")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("empty=compileClasspath\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "gradle.lockfile"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = gradle.New().Dependencies(dir)
	})
}
