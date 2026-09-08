package verify_test

import (
	"testing"

	"github.com/securock/securock/internal/verify"
	"github.com/securock/securock/pkg/lockfile"
)

func TestCompare(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"}, Version: "19.1.0", Digest: "sha256:aaa"},
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "old"}, Version: "1.0.0"},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:bbb",
			Trust:   lockfile.Trust{Status: lockfile.StatusTrusted},
		},
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "lodash"},
			Version: "4.17.21",
			Trust:   lockfile.Trust{Status: lockfile.StatusUntrusted, Reasons: []string{"known vulnerabilities"}},
		},
	}}

	got := verify.Compare(locked, current)
	if len(got.Findings) != 3 {
		t.Fatalf("got %d findings: %s", len(got.Findings), got.Error())
	}
}

func TestCompareVersionChangeKeepsSubject(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"}, Version: "19.1.0", Digest: "sha256:aaa"},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"}, Version: "19.2.0", Digest: "sha256:aaa"},
	}}

	got := verify.Compare(locked, current)
	if len(got.Findings) != 0 {
		t.Fatalf("version-only change should keep subject identity: %s", got.Error())
	}
}
