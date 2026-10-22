package exceptions_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/exceptions"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte("version: 1\nexceptions:\n  - id: a\n    reason: r\n    expires: 2026-12-31\n"))
	f.Add([]byte("version: [\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(t.TempDir(), "e.yaml")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Skip()
		}
		_, _ = exceptions.Load(path)
	})
}
