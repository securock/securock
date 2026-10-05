package lockfile_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/pkg/lockfile"
)

func TestValidateOutdatedVersion(t *testing.T) {
	err := lockfile.Validate(lockfile.Document{Version: 1})
	if err == nil {
		t.Fatal("expected outdated version error")
	}
	if !strings.Contains(err.Error(), "outdated") || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnsupportedFutureVersion(t *testing.T) {
	err := lockfile.Validate(lockfile.Document{Version: 99})
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
}
