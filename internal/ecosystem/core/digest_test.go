package core_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
)

func TestNormalizeDigest(t *testing.T) {
	got := core.NormalizeDigest("sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
	want := "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	h1 := core.NormalizeDigest("h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
	if h1 != "goh1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" {
		t.Fatalf("h1 digest = %q", h1)
	}
}

func TestMatchDigest(t *testing.T) {
	data := []byte("test")
	normalized := core.NormalizeDigest("sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
	if err := core.MatchDigest(normalized, data); err != nil {
		t.Fatalf("MatchDigest: %v", err)
	}
	if err := core.MatchDigest(normalized, []byte("other")); err == nil {
		t.Fatal("expected mismatch")
	}
	if err := core.MatchDigest("", data); err == nil {
		t.Fatal("expected missing digest error")
	}
}
