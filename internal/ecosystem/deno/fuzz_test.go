package deno_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/deno"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/deno.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"version":"5","npm":{},"jsr":{},"remote":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "deno.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = deno.New().Dependencies(dir)
	})
}
