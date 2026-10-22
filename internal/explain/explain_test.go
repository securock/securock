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

func TestExplainReachability(t *testing.T) {
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{{
		Subject: lockfile.Subject{Ecosystem: "npm", Name: "shared"},
		Version: "1.0.0",
		Evidence: lockfile.Evidence{
			Vulnerabilities: lockfile.VulnEvidence{
				State: lockfile.VulnChecked,
				Items: []lockfile.Vulnerability{
					{ID: "V-DIRECT", Reachable: lockfile.ReachYes},
					{ID: "V-VIA", Reachable: lockfile.ReachYes, Via: []string{"npm:app@1.0.0", "npm:shared@1.0.0"}},
					{ID: "V-DEV", Reachable: lockfile.ReachNo},
					{ID: "V-UNKNOWN", Reachable: lockfile.ReachUnknown},
					{ID: "V-NOTRECORDED"},
				},
			},
		},
	}}}
	res, err := explain.Find(doc, "shared")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	explain.Write(&buf, res)
	for _, want := range []string{
		"V-DIRECT reachable at runtime (direct runtime dependency)",
		"V-VIA reachable at runtime via npm:app@1.0.0 -> npm:shared@1.0.0",
		"V-DEV not reachable: development dependency only",
		"V-UNKNOWN reachability unknown",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "V-NOTRECORDED reach") {
		t.Fatalf("nothing should be said when reachability was not recorded:\n%s", buf.String())
	}
}

func TestExplainAdvisoryDetail(t *testing.T) {
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{{
		Subject: lockfile.Subject{Ecosystem: "npm", Name: "lodash"},
		Version: "4.17.20",
		Evidence: lockfile.Evidence{Vulnerabilities: lockfile.VulnEvidence{
			State: lockfile.VulnChecked,
			Items: []lockfile.Vulnerability{
				{ID: "V-BOTH", Severity: lockfile.SeverityHigh, Fixed: []string{"4.17.21", "5.0.1"}},
				{ID: "V-SEV", Severity: lockfile.SeverityLow},
				{ID: "V-FIX", Fixed: []string{"4.17.21"}},
				{ID: "V-NONE"},
			},
		}},
	}}}
	res, err := explain.Find(doc, "lodash")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	explain.Write(&buf, res)
	for _, want := range []string{"V-BOTH high severity, fixed in 4.17.21, 5.0.1", "V-SEV low severity", "V-FIX fixed in 4.17.21"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "V-NONE ") {
		t.Fatalf("an advisory with no detail adds no line:\n%s", buf.String())
	}
}
