package remediation_test

import (
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/remediation"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewablePatchAndStaleGuard(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "a.go")
	os.WriteFile(p, []byte("package p\nvar x = tls.Config{InsecureSkipVerify: true}\n"), 0600)
	f := finding.Finding{ID: "sast:go/tls-verification-disabled", Location: &finding.Location{File: "a.go", Line: 2}}
	patch, e := remediation.Patch(d, f)
	if e != nil || !strings.Contains(patch, "InsecureSkipVerify: false") {
		t.Fatal(patch, e)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), ": true") {
		t.Fatal("source modified")
	}
	f.Location.Line = 1
	if _, e := remediation.Patch(d, f); e == nil {
		t.Fatal("stale location accepted")
	}
}
