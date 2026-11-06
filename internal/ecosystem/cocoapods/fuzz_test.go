package cocoapods_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cocoapods"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/Podfile.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("PODS: []\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Podfile.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = cocoapods.New().Dependencies(dir)
	})
}
