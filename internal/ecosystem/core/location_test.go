package core_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
)

func TestRemoteLocation(t *testing.T) {
	got := core.RemoteLocation("https://user:pass@github.com/example/foo.git?rev=main#abc")
	if got != "https://github.com/example/foo.git" {
		t.Fatalf("got %q", got)
	}
	if core.RemoteLocation("../foo") != "" || core.RemoteLocation("file:///tmp/foo") != "" {
		t.Fatal("local paths must be omitted")
	}
	if core.RemoteRevision("https://github.com/example/foo.git#abc123") != "abc123" {
		t.Fatal("missing fragment revision")
	}
}
