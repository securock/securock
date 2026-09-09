package schemas_test

import (
	"testing"

	"github.com/securock/securock/schemas"
)

func TestURLArtifactOmitsVersion(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "artifacts": [
    {
      "subject": { "ecosystem": "url", "name": "https://esm.sh/preact" },
      "source": {
        "resolver": "deno",
        "requested": "https://esm.sh/preact",
        "resolved": "https://esm.sh/preact@10.26.8"
      },
      "evidence": {
        "provenance": "unknown",
        "signature": "unknown",
        "vulnerabilities": { "state": "unknown" }
      },
      "trust": { "status": "unknown" }
    }
  ]
}`)
	if err := schemas.Validate("scan-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
}

func TestNPMArtifactRequiresVersion(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "artifacts": [
    {
      "subject": { "ecosystem": "npm", "name": "react" },
      "evidence": {
        "provenance": "unknown",
        "signature": "unknown",
        "vulnerabilities": { "state": "unknown" }
      },
      "trust": { "status": "unknown" }
    }
  ]
}`)
	if err := schemas.Validate("scan-report.schema.json", raw); err == nil {
		t.Fatal("npm artifacts must require version")
	}
}

func TestDiffSideRequestedResolved(t *testing.T) {
	raw := []byte(`{
  "schema_version": 1,
  "trust_drift": true,
  "changes": [
    {
      "artifact": "url:https://esm.sh/preact",
      "subject": "url:https://esm.sh/preact",
      "before": {
        "requested": ["https://esm.sh/preact"],
        "resolved": ["https://esm.sh/preact@10.26.8"]
      },
      "after": {
        "requested": ["https://esm.sh/preact"],
        "resolved": ["https://esm.sh/preact@10.26.9"]
      }
    }
  ]
}`)
	if err := schemas.Validate("diff-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
	if err := schemas.Validate("verify-report.schema.json", raw); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsUnknownArtifactField(t *testing.T) {
	raw := []byte(`{
  "version": 1,
  "artifacts": [
    {
      "subject": { "ecosystem": "npm", "name": "react" },
      "version": "19.2.0",
      "banana": true,
      "evidence": {
        "provenance": "unknown",
        "signature": "unknown",
        "vulnerabilities": { "state": "unknown" }
      },
      "trust": { "status": "unknown" }
    }
  ]
}`)
	if err := schemas.Validate("scan-report.schema.json", raw); err == nil {
		t.Fatal("unknown fields must fail")
	}
}
