package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/quality"
	"github.com/securock/securock/schemas"
)

func TestQualityPerRuleOutputAndSchema(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	fixtures := filepath.Join(root, "fixtures")
	os.MkdirAll(fixtures, 0700)
	os.WriteFile(filepath.Join(fixtures, "app.py"), []byte("import requests\ndef f():\n    return requests.get('https://example.test', verify=False)\n"), 0600)
	suite := filepath.Join(root, "suite.json")
	raw, _ := json.Marshal(map[string]any{"version": 1, "steps": []any{map[string]any{"name": "python-tls", "command": "security", "args": []string{fixtures}, "expected": []string{"sast:py/tls-verification-disabled", "security:dependencies-unchecked"}, "forbidden": []string{"sast:py/sql-injection"}}}})
	os.WriteFile(suite, raw, 0600)
	out := runCLI(t, "quality", suite, "--fixture-root", fixtures, "--per-rule", "--max-fpr", "0.02", "--offline")
	if err := schemas.Validate("quality-report.schema.json", out); err != nil {
		t.Fatal(err)
	}
	var report quality.Report
	if err := json.Unmarshal(out, &report); err != nil || !report.Passed || len(report.Rules) != 3 {
		t.Fatalf("%s err=%v", out, err)
	}
}
