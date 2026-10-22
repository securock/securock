package sbom

import (
	"fmt"
	"sort"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/pkg/lockfile"
)

const regenerate = "Regenerate the SBOM with securock sbom export."

// Verify compares an SBOM against the lockfile. Every difference is a high finding,
// because an SBOM that disagrees with the lock misdescribes what was trusted.
func Verify(lock lockfile.Document, sbom Document) finding.Report {
	byID := make(map[string]lockfile.Artifact, len(lock.Artifacts))
	byPURL := make(map[string]string, len(lock.Artifacts))
	for _, a := range lock.Artifacts {
		byID[a.ArtifactID()] = a
		if p := PURL(a); p != "" {
			if _, dup := byPURL[p]; !dup {
				byPURL[p] = a.ArtifactID()
			}
		}
	}

	var out []finding.Finding
	add := func(id, title, subject, detail string) {
		out = append(out, finding.Finding{ID: id, Severity: finding.SeverityHigh, Title: title, Subject: subject, Detail: detail, Remediation: regenerate})
	}

	if sbom.PolicyDigest != "" && sbom.PolicyDigest != lock.Policy.Digest {
		add("sbom-policy-mismatch", "SBOM was exported under a different policy", "", mismatch(sbom.PolicyDigest, lock.Policy.Digest))
	}

	matched := map[string]bool{}
	entries := append([]Entry(nil), sbom.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entryName(entries[i]) < entryName(entries[j]) })
	for _, e := range entries {
		id := first(e.Props[PropArtifact])
		if id == "" {
			id = byPURL[e.PURL]
		}
		a, ok := byID[id]
		if !ok {
			add("sbom-component-unexpected", "SBOM lists a package that is not in the lockfile", entryName(e), "")
			continue
		}
		if matched[id] {
			continue
		}
		matched[id] = true

		if e.Version != a.Version {
			add("sbom-version-mismatch", "SBOM version differs from the lockfile", id, mismatch(e.Version, a.Version))
		}
		if want := PURL(a); want != "" && e.PURL != want {
			add("sbom-purl-mismatch", "SBOM package URL differs from the lockfile", id, mismatch(e.PURL, want))
		}
		if a.Digest != "" && e.Digest != a.Digest {
			add("sbom-digest-mismatch", "SBOM digest differs from the lockfile", id, mismatch(e.Digest, a.Digest))
		}
		if status := first(e.Props[PropTrustStatus]); status != "" && status != string(a.Trust.Status) {
			add("sbom-trust-mismatch", "SBOM trust status differs from the lockfile", id, mismatch(status, string(a.Trust.Status)))
		}
	}

	for _, a := range lock.Artifacts {
		if !matched[a.ArtifactID()] {
			add("sbom-component-missing", "Lockfile package is missing from the SBOM", a.ArtifactID(), "")
		}
	}
	return finding.New("sbom-verify", out)
}

func entryName(e Entry) string {
	if id := first(e.Props[PropArtifact]); id != "" {
		return id
	}
	if e.PURL != "" {
		return e.PURL
	}
	if e.Version != "" {
		return e.Name + "@" + e.Version
	}
	return e.Name
}

func mismatch(sbom, lock string) string {
	return fmt.Sprintf("sbom %q, lockfile %q", sbom, lock)
}
