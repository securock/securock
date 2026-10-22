package diff_test

import (
	"strings"
	"testing"

	"github.com/securock/securock/internal/diff"
	"github.com/securock/securock/pkg/lockfile"
)

func art(name, version, digest string, status lockfile.Status) lockfile.Artifact {
	return lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: "npm", Name: name},
		Version: version,
		Digest:  digest,
		Trust:   lockfile.Trust{Status: status},
	}
}

func TestFindingsReportTrustDrift(t *testing.T) {
	locked := lockfile.Document{
		Policy: lockfile.PolicyRef{Digest: "sha256:old"},
		Artifacts: []lockfile.Artifact{
			art("react", "19.1.0", "sha256:aaa", lockfile.StatusTrusted),
			art("gone", "1.0.0", "sha256:ccc", lockfile.StatusTrusted),
		},
	}
	current := lockfile.Document{
		Policy: lockfile.PolicyRef{Digest: "sha256:new"},
		Artifacts: []lockfile.Artifact{
			art("react", "19.2.0", "sha256:bbb", lockfile.StatusTrusted),
			art("fresh", "2.0.0", "sha256:ddd", lockfile.StatusTrusted),
		},
	}

	report := diff.Compare(locked, current).Findings("verify")
	if report.Tool != "verify" {
		t.Fatalf("tool: %s", report.Tool)
	}
	ids := map[string]string{}
	for _, f := range report.Findings {
		ids[f.ID+"|"+f.Subject] = f.Detail
	}
	if len(report.Findings) != 4 {
		t.Fatalf("findings: %+v", report.Findings)
	}
	for _, key := range []string{"policy-changed|", "artifact-removed|npm:gone", "artifact-added|npm:fresh"} {
		if _, ok := ids[key]; !ok {
			t.Fatalf("missing %s in %v", key, ids)
		}
	}
	var drift string
	for key, detail := range ids {
		if strings.HasPrefix(key, "trust-drift|") {
			drift = detail
		}
	}
	if !strings.Contains(drift, "version") || !strings.Contains(drift, "digest") {
		t.Fatalf("trust-drift detail should name changed fields: %q", drift)
	}
}

func TestFindingsEmptyWithoutDrift(t *testing.T) {
	doc := lockfile.Document{Artifacts: []lockfile.Artifact{art("react", "19.1.0", "sha256:aaa", lockfile.StatusTrusted)}}
	report := diff.Compare(doc, doc).Findings("diff")
	if len(report.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
}
