package nuget_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/nuget"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/packages.lock.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"version":1,"dependencies":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = nuget.New().Dependencies(dir)
	})
}
