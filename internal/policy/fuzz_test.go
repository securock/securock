package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/policy"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte("version: 1\nrules:\n  require_no_vulnerabilities: true\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = policy.Load(path)
	})
}
