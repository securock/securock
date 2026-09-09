package pub_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/pub"
)

func FuzzDependencies(f *testing.F) {
	seed, err := os.ReadFile("testdata/pubspec.lock")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("packages: {}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pubspec.lock"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = pub.New().Dependencies(dir)
	})
}
