package bundler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/bundler"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/Gemfile.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("GEM\n  remote: https://rubygems.org/\n  specs:\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = bundler.New().Dependencies(dir)
	})
}
