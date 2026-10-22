package cli_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/pkg/lockfile"
)

// vulnerableProject writes a lockfile that records one advisory against lodash.
func vulnerableProject(t *testing.T) string {
	t.Helper()
	isolateHome(t)
	dir := t.TempDir()
	doc := lockfile.Document{
		Version: lockfile.SchemaVersion,
		Artifacts: []lockfile.Artifact{{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "lodash"},
			Version: "4.17.20",
			Evidence: lockfile.Evidence{
				Provenance:      lockfile.EvidenceUnknown,
				Signature:       lockfile.EvidenceUnknown,
				Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnChecked, Items: []lockfile.Vulnerability{{ID: "GHSA-1"}}},
				Malicious:       lockfile.MaliciousEvidence{State: lockfile.VulnChecked},
				Capabilities:    lockfile.CapabilityEvidence{State: lockfile.CapUnknown},
				Behavior:        lockfile.BehaviorEvidence{State: lockfile.CapUnknown},
				Ownership:       lockfile.OwnershipEvidence{State: lockfile.CapUnknown},
				Chain:           lockfile.ChainEvidence{State: lockfile.EvidenceUnknown},
			},
			Trust: lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerabilities"}},
		}},
	}
	if err := lock.Write(filepath.Join(dir, "securock.lock"), doc); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVEXExport(t *testing.T) {
	dir := vulnerableProject(t)
	runCLI(t, "accept", "known-vulnerability:GHSA-1", dir, "--reason", "only used by a build script", "--approver", "alice", "--expires", "90d")

	t.Setenv("SOURCE_DATE_EPOCH", "1781515800")
	var openvex struct {
		Author     string
		Timestamp  string
		Statements []struct {
			Status          string
			ActionStatement string `json:"action_statement"`
			Products        []struct {
				ID string `json:"@id"`
			}
		}
	}
	out := runCLI(t, "vex", "export", dir, "--author", "Security Team")
	if err := json.Unmarshal(out, &openvex); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if openvex.Author != "Security Team" || openvex.Timestamp != "2026-06-15T09:30:00Z" ||
		len(openvex.Statements) != 1 || openvex.Statements[0].Status != "affected" ||
		openvex.Statements[0].Products[0].ID != "pkg:npm/lodash@4.17.20" ||
		!strings.Contains(openvex.Statements[0].ActionStatement, "only used by a build script") {
		t.Fatalf("openvex:\n%s", out)
	}
	if again := runCLI(t, "vex", "export", dir, "--author", "Security Team"); !bytes.Equal(out, again) {
		t.Fatal("export must be deterministic when SOURCE_DATE_EPOCH is set")
	}

	// Renewing with a justification turns the statement into not_affected.
	runCLI(t, "accept", "known-vulnerability:GHSA-1", dir, "--reason", "never called", "--expires", "90d", "--justification", "vulnerable_code_not_in_execute_path")
	out = runCLI(t, "vex", "export", dir, "--author", "Security Team")
	if !bytes.Contains(out, []byte(`"status": "not_affected"`)) || !bytes.Contains(out, []byte(`"justification": "vulnerable_code_not_in_execute_path"`)) {
		t.Fatalf("openvex:\n%s", out)
	}

	cdx := runCLI(t, "vex", "export", dir, "--author", "Security Team", "--spec", "cyclonedx")
	if !bytes.Contains(cdx, []byte(`"state": "not_affected"`)) || !bytes.Contains(cdx, []byte(`"justification": "code_not_reachable"`)) {
		t.Fatalf("cyclonedx:\n%s", cdx)
	}
}

func TestVEXExportErrors(t *testing.T) {
	dir := vulnerableProject(t)
	for name, args := range map[string][]string{
		"no author":        {"vex", "export", dir},
		"unknown spec":     {"vex", "export", dir, "--author", "a", "--spec", "csaf"},
		"no lockfile":      {"vex", "export", t.TempDir(), "--author", "a"},
		"bad exceptions":   {"vex", "export", dir, "--author", "a", "--exceptions", filepath.Join(dir, "securock.lock")},
		"nothing accepted": {"vex", "export", dir, "--author", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runCLIErr(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestAcceptJustificationValidation(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"unknown justification": {"accept", "known-vulnerability:G", dir, "--reason", "r", "--expires", "30d", "--justification", "because"},
		"not a vulnerability":   {"accept", "capability:network", dir, "--reason", "r", "--expires", "30d", "--justification", "component_not_present"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runCLIErr(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	runCLI(t, "accept", "known-vulnerability:G", dir, "--reason", "r", "--expires", "30d", "--justification", "component_not_present")
}
