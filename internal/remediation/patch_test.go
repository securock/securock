package remediation_test

import (
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/remediation"
	"github.com/securock/securock/internal/sast"
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

func TestTLSFixesUseSyntaxAndCurrentEvidence(t *testing.T) {
	for _, tc := range []struct{ name, file, source, id, want string }{
		{"python", "app.py", "import requests\ndef f():\n    return requests.get('https://example.test', verify=False)\n", "sast:py/tls-verification-disabled", "verify=True"},
		{"javascript", "app.js", "const https = require('https');\nconst agent = new https.Agent({rejectUnauthorized: false});\n", "sast:js/tls-verification-disabled", "rejectUnauthorized: true"},
		{"go assignment", "app.go", "package p\nimport \"crypto/tls\"\nfunc f(c *tls.Config) { c.InsecureSkipVerify = true }\n", "sast:go/tls-verification-disabled", "InsecureSkipVerify = false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			os.WriteFile(filepath.Join(d, tc.file), []byte(tc.source), 0600)
			found, err := sast.Analyze(d)
			if err != nil {
				t.Fatal(err)
			}
			var target *finding.Finding
			for i := range found {
				if found[i].ID == tc.id {
					target = &found[i]
					break
				}
			}
			if target == nil {
				t.Fatalf("missing fixture finding: %+v", found)
			}
			patch, err := remediation.Patch(d, *target)
			if err != nil || !strings.Contains(patch, tc.want) {
				t.Fatalf("patch=%s err=%v", patch, err)
			}
			raw, _ := os.ReadFile(filepath.Join(d, tc.file))
			if string(raw) != tc.source {
				t.Fatal("source modified")
			}
		})
	}
}

func TestTLSFixRejectsCommentAndStringDecoys(t *testing.T) {
	for _, source := range []string{
		"package p\n// InsecureSkipVerify: true\n",
		"package p\nvar note = `InsecureSkipVerify: true`\n",
	} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "app.go"), []byte(source), 0600)
		_, err := remediation.Patch(d, finding.Finding{ID: "sast:go/tls-verification-disabled", Location: &finding.Location{File: "app.go", Line: 2}})
		if err == nil {
			t.Fatal("accepted a comment or string as a TLS setting")
		}
	}
}
