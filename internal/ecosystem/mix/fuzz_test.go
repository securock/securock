package mix_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/mix"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/mix.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("%{}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "mix.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = mix.New().Dependencies(dir)
	})
}
