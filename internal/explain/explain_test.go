package explain_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/securock/securock/internal/explain"
	"github.com/securock/securock/pkg/lockfile"
)

func TestExplainTrustedPackage(t *testing.T) {
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			Source:  lockfile.ArtifactSource{Registry: "https://registry.npmjs.org"},
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidencePresent,
				Signature:  lockfile.EvidencePresent,
				Vulnerabilities: lockfile.VulnEvidence{
					State: lockfile.VulnChecked,
				},
				Malicious: lockfile.MaliciousEvidence{
					State: lockfile.VulnChecked,
				},
				Capabilities: lockfile.CapabilityEvidence{
					State:   lockfile.CapChecked,
					Network: lockfile.Bool(false),
				},
				Ownership: lockfile.OwnershipEvidence{
					State:     lockfile.CapChecked,
					Publisher: "alice",
				},
				Chain: lockfile.ChainEvidence{
					State:    lockfile.EvidencePresent,
					Source:   "github.com/facebook/react",
					Commit:   "abc123",
					Builder:  "https://github.com/actions/runner",
					Workflow: "release.yml",
				},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusTrusted},
		},
	}}
	got, err := explain.Find(doc, "react")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	explain.Write(&buf, got)
	out := buf.String()
	for _, want := range []string{
		"Why is react trusted?",
		"✓ digest matches",
		"✓ registry proven",
		"✓ provenance present",
		"✓ trust chain",
		"source     github.com/facebook/react",
		"workflow   release.yml",
		"✓ publisher recorded",
		"✓ capabilities locked",
		"✓ no known vulnerabilities",
		"✓ no malicious package reports",
		"verdict  trusted",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestExplainNotFound(t *testing.T) {
	_, err := explain.Find(lockfile.Document{}, "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExplainHealth(t *testing.T) {
	art := func(name string, h *lockfile.HealthEvidence) lockfile.Artifact {
		return lockfile.Artifact{
			Subject:  lockfile.Subject{Ecosystem: "npm", Name: name},
			Version:  "1.0.0",
			Evidence: lockfile.Evidence{Health: h},
		}
	}
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{
		art("steady", &lockfile.HealthEvidence{Released: "2025-01-31", License: "MIT"}),
		art("retired", &lockfile.HealthEvidence{Deprecated: "use steady"}),
		art("unchecked", nil),
		art("lodahs", nil),
	}}
	tests := []struct {
		query string
		want  []string
	}{
		{"steady", []string{"✓ release is not deprecated", "released   2025-01-31", "license    MIT"}},
		{"retired", []string{"✗ release is deprecated (use steady)"}},
		{"unchecked", []string{"? release health not checked"}},
		{"lodahs", []string{"✗ name resembles a popular package (lodash)"}},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			res, err := explain.Find(doc, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			explain.Write(&buf, res)
			for _, want := range tt.want {
				if !strings.Contains(buf.String(), want) {
					t.Fatalf("missing %q in:\n%s", want, buf.String())
				}
			}
		})
	}
}
