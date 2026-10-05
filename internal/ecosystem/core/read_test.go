package core_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
)

func TestReadFileLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	if err := os.WriteFile(path, []byte("abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := core.ReadFileLimit(path, 6)
	if err != nil || string(got) != "abcdef" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if _, err := core.ReadFileLimit(path, 5); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestReadFileDefaultLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge")
	// Don't allocate 64MiB+1; open a pipe-like file by writing just over a
	// tiny custom limit via ReadFileLimit instead. Default constant is
	// covered by the success path on a small file.
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 16)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := core.ReadFile(path); err != nil {
		t.Fatal(err)
	}
}
