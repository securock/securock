package lockfile_test

import (
	"testing"

	"github.com/securock/securock/pkg/lockfile"
)

func TestCanonicalize(t *testing.T) {
	doc := lockfile.Document{
		Version: 1,
		Source: lockfile.Source{
			Ecosystems: []string{"go", "npm", "npm"},
		},
		Artifacts: []lockfile.Artifact{
			{Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"}, Version: "19.2.0"},
			{Subject: lockfile.Subject{Ecosystem: "npm", Name: "lodash"}, Version: "4.17.21"},
		},
	}
	doc.Artifacts[0].Evidence.Vulnerabilities = lockfile.VulnEvidence{
		State: lockfile.VulnChecked,
		Items: []lockfile.Vulnerability{
			{ID: "GHSA-b"},
			{ID: "GHSA-a"},
		},
	}
	lockfile.Canonicalize(&doc)

	if got := doc.Source.Ecosystems; len(got) != 2 || got[0] != "go" || got[1] != "npm" {
		t.Fatalf("ecosystems = %v", got)
	}
	if doc.Artifacts[0].Subject.Name != "lodash" {
		t.Fatalf("first artifact = %s", doc.Artifacts[0].Subject.Name)
	}
	if doc.Artifacts[1].Evidence.Vulnerabilities.Items[0].ID != "GHSA-a" {
		t.Fatalf("vulns not sorted: %#v", doc.Artifacts[1].Evidence.Vulnerabilities)
	}
}

func TestSubjectIdentity(t *testing.T) {
	art := lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
		Version: "19.2.0",
	}
	if art.Identity() != "npm:react" {
		t.Fatalf("identity = %s", art.Identity())
	}
	if art.ArtifactID() != "npm:react@19.2.0" {
		t.Fatalf("artifact id = %s", art.ArtifactID())
	}
	art.Filename = "react-19.2.0.tgz"
	if art.ArtifactID() != "npm:react@19.2.0#react-19.2.0.tgz" {
		t.Fatalf("artifact id with filename = %s", art.ArtifactID())
	}
}

func TestURLArtifactIDOmitsEmptyVersion(t *testing.T) {
	art := lockfile.Artifact{
		Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
	}
	if art.SubjectID() != "url:https://esm.sh/preact" {
		t.Fatalf("subject = %s", art.SubjectID())
	}
	if art.ArtifactID() != "url:https://esm.sh/preact" {
		t.Fatalf("url artifact id = %s", art.ArtifactID())
	}
}

func TestValidateAllowsEmptyURLVersion(t *testing.T) {
	doc := lockfile.Document{
		Version: 1,
		Artifacts: []lockfile.Artifact{
			{
				Subject: lockfile.Subject{Ecosystem: "url", Name: "https://esm.sh/preact"},
				Source: lockfile.ArtifactSource{
					Resolver:  "deno",
					Requested: "https://esm.sh/preact",
					Resolved:  "https://esm.sh/preact@10.26.8",
				},
				Evidence: lockfile.Evidence{
					Provenance:      lockfile.EvidenceUnknown,
					Signature:       lockfile.EvidenceUnknown,
					Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnUnknown},
				},
				Trust: lockfile.Trust{Status: lockfile.StatusUnknown},
			},
		},
	}
	if err := lockfile.Validate(doc); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsEmptyNPMVersion(t *testing.T) {
	doc := lockfile.Document{
		Version: 1,
		Artifacts: []lockfile.Artifact{
			{
				Subject: lockfile.Subject{Ecosystem: "npm", Name: "react"},
				Evidence: lockfile.Evidence{
					Provenance:      lockfile.EvidenceUnknown,
					Signature:       lockfile.EvidenceUnknown,
					Vulnerabilities: lockfile.VulnEvidence{State: lockfile.VulnUnknown},
				},
				Trust: lockfile.Trust{Status: lockfile.StatusUnknown},
			},
		},
	}
	if err := lockfile.Validate(doc); err == nil {
		t.Fatal("npm artifacts must require a version")
	}
}
