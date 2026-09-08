package verify_test

import (
	"testing"

	"github.com/securock/securock/internal/verify"
	"github.com/securock/securock/pkg/lockfile"
)

func TestCompareTrustDrift(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"}, Version: "19.1.0", Digest: "sha256:aaa"},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.2.0",
			Digest:  "sha256:bbb",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidencePresent,
			},
		},
	}}

	got := verify.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("digest change must fail verify")
	}
}

func TestCompareProvenanceDrift(t *testing.T) {
	locked := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.1.0",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidencePresent,
			},
		},
	}}
	current := lockfile.Document{Artifacts: []lockfile.Artifact{
		{
			Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
			Version: "19.1.0",
			Evidence: lockfile.Evidence{
				Provenance: lockfile.EvidenceMissing,
			},
		},
	}}

	got := verify.Compare(locked, current)
	if !got.TrustDrift() {
		t.Fatal("provenance change must fail verify")
	}
}
