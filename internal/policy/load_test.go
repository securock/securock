package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/policy"
)

func TestLoadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nrules:\n  require_provenace: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(path); err == nil {
		t.Fatal("expected typo to fail closed")
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 9\nrules:\n  require_no_vulnerabilities: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(path); err == nil {
		t.Fatal("expected unknown version to fail")
	}
}
