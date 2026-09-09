package bun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/bun"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/bun.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"lockfileVersion":1,"packages":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "bun.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = bun.New().Dependencies(dir)
	})
}
