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
	doc.Artifacts[0].Evidence.Vulnerabilities = []lockfile.Vulnerability{
		{ID: "GHSA-b"},
		{ID: "GHSA-a"},
	}
	lockfile.Canonicalize(&doc)

	if got := doc.Source.Ecosystems; len(got) != 2 || got[0] != "go" || got[1] != "npm" {
		t.Fatalf("ecosystems = %v", got)
	}
	if doc.Artifacts[0].Subject.Name != "lodash" {
		t.Fatalf("first artifact = %s", doc.Artifacts[0].Subject.Name)
	}
	if doc.Artifacts[1].Evidence.Vulnerabilities[0].ID != "GHSA-a" {
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
}
