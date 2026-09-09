package evidence_test

import (
	"testing"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
)

func TestKeyIncludesFilename(t *testing.T) {
	got := evidence.Key(ecosystem.Dependency{
		Ecosystem: "pypi",
		Name:      "foo",
		Version:   "1.0.0",
		Filename:  "foo-linux.whl",
	})
	if got != "pypi:foo@1.0.0#foo-linux.whl" {
		t.Fatalf("got %q", got)
	}
}
