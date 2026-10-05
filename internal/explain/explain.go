package explain

import (
	"fmt"
	"io"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

type Result struct {
	Subject   string
	Artifacts []lockfile.Artifact
}

func Find(doc lockfile.Document, query string) (Result, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return Result{}, fmt.Errorf("package name required")
	}

	var matches []lockfile.Artifact
	for _, art := range doc.Artifacts {
		if match(art, query) {
			matches = append(matches, art)
		}
	}
	if len(matches) == 0 {
		return Result{}, fmt.Errorf("package %q not found", query)
	}
	return Result{
		Subject:   matches[0].SubjectID(),
		Artifacts: matches,
	}, nil
}

func Write(w io.Writer, r Result) {
	name := r.Artifacts[0].Subject.Name
	fmt.Fprintf(w, "Why is %s trusted?\n\n", name)

	for i, art := range r.Artifacts {
		if len(r.Artifacts) > 1 {
			label := art.ArtifactID()
			fmt.Fprintf(w, "%s\n", label)
		} else if art.Version != "" {
			fmt.Fprintf(w, "%s@%s\n", name, art.Version)
		}
		writeChecks(w, art)
		if i+1 < len(r.Artifacts) {
			fmt.Fprintln(w)
		}
	}
}

func writeChecks(w io.Writer, art lockfile.Artifact) {
	writeCheck(w, art.Digest != "", "digest matches", "digest missing")
	writeSource(w, art)
	writeEvidence(w, "provenance verified", "provenance present", "provenance missing", "provenance not checked", art.Evidence.Provenance)
	writeEvidence(w, "signature verified", "signature present", "signature missing", "signature not checked", art.Evidence.Signature)
	writeChain(w, art)
	writeOwnership(w, art.Evidence.Ownership)
	writeCapabilities(w, art.Evidence.Capabilities)
	writeVulns(w, art.Evidence.Vulnerabilities)
	writeMalicious(w, art.Evidence.Malicious)
	writeTrust(w, art.Trust)
}

func writeChain(w io.Writer, art lockfile.Artifact) {
	chain := art.Evidence.Chain
	switch chain.State {
	case lockfile.EvidencePresent, lockfile.EvidenceVerified:
		fmt.Fprintln(w, "✓ trust chain")
		if chain.Source != "" {
			fmt.Fprintf(w, "  source     %s\n", chain.Source)
		}
		if chain.Commit != "" {
			fmt.Fprintf(w, "  commit     %s\n", chain.Commit)
		}
		if chain.Builder != "" {
			fmt.Fprintf(w, "  builder    %s\n", chain.Builder)
		}
		if chain.Workflow != "" {
			fmt.Fprintf(w, "  workflow   %s\n", chain.Workflow)
		}
		fmt.Fprintln(w, "  Chain")
		writeChainStep(w, "source", chain.Source != "")
		fmt.Fprintln(w, "       ↓")
		writeChainStep(w, "workflow", chain.Workflow != "" || chain.Builder != "")
		fmt.Fprintln(w, "       ↓")
		writeChainStep(w, "provenance", art.Evidence.Provenance.Present())
		fmt.Fprintln(w, "       ↓")
		writeChainStep(w, "artifact", art.Digest != "")
	case lockfile.EvidenceMissing:
		fmt.Fprintln(w, "✗ trust chain missing")
	default:
		fmt.Fprintln(w, "? trust chain not checked")
	}
}

func writeChainStep(w io.Writer, name string, ok bool) {
	mark := "✗"
	if ok {
		mark = "✓"
	}
	fmt.Fprintf(w, "  %-10s %s\n", name, mark)
}

func writeSource(w io.Writer, art lockfile.Artifact) {
	switch {
	case art.Source.Registry != "":
		fmt.Fprintf(w, "✓ registry proven (%s)\n", art.Source.Registry)
	case art.Source.Kind == "git" && art.Source.Artifact != "":
		fmt.Fprintf(w, "✓ git source (%s)\n", art.Source.Artifact)
	case art.Source.Kind != "":
		fmt.Fprintf(w, "✓ source kind %s\n", art.Source.Kind)
	default:
		fmt.Fprintln(w, "? source not recorded")
	}
}

func writeEvidence(w io.Writer, verified, present, missing, unknown string, state lockfile.EvidenceState) {
	switch state {
	case lockfile.EvidenceVerified:
		fmt.Fprintf(w, "✓ %s\n", verified)
	case lockfile.EvidencePresent:
		fmt.Fprintf(w, "✓ %s\n", present)
	case lockfile.EvidenceMissing:
		fmt.Fprintf(w, "✗ %s\n", missing)
	default:
		fmt.Fprintf(w, "? %s\n", unknown)
	}
}

func writeOwnership(w io.Writer, own lockfile.OwnershipEvidence) {
	switch own.State {
	case lockfile.CapChecked:
		if own.Publisher != "" {
			fmt.Fprintf(w, "✓ publisher recorded (%s)\n", own.Publisher)
		} else {
			fmt.Fprintln(w, "✓ publisher recorded (none listed)")
		}
		if len(own.Maintainers) > 0 {
			fmt.Fprintf(w, "✓ maintainers recorded (%s)\n", strings.Join(own.Maintainers, ", "))
		} else {
			fmt.Fprintln(w, "✓ maintainers recorded (none listed)")
		}
	default:
		fmt.Fprintln(w, "? ownership not checked")
	}
}

func writeCapabilities(w io.Writer, caps lockfile.CapabilityEvidence) {
	switch caps.State {
	case lockfile.CapChecked:
		fmt.Fprintf(w, "✓ capabilities locked (%s)\n", summarizeCaps(caps))
	default:
		fmt.Fprintln(w, "? capabilities not checked")
	}
}

func writeVulns(w io.Writer, vulns lockfile.VulnEvidence) {
	switch vulns.State {
	case lockfile.VulnChecked:
		if len(vulns.Items) == 0 {
			fmt.Fprintln(w, "✓ no known vulnerabilities")
		} else {
			ids := make([]string, 0, len(vulns.Items))
			for _, v := range vulns.Items {
				ids = append(ids, v.ID)
			}
			fmt.Fprintf(w, "✗ known vulnerabilities (%s)\n", strings.Join(ids, ", "))
		}
	default:
		fmt.Fprintln(w, "? vulnerabilities not checked")
	}
}

func writeMalicious(w io.Writer, mal lockfile.MaliciousEvidence) {
	switch mal.State {
	case lockfile.VulnChecked:
		if len(mal.Reports) == 0 {
			fmt.Fprintln(w, "✓ no malicious package reports")
		} else {
			ids := make([]string, 0, len(mal.Reports))
			for _, r := range mal.Reports {
				ids = append(ids, r.ID)
			}
			fmt.Fprintf(w, "✗ malicious package\n")
			fmt.Fprintln(w, "  OpenSSF Malicious Packages")
			for _, id := range ids {
				fmt.Fprintf(w, "    %s\n", id)
			}
		}
	default:
		fmt.Fprintln(w, "? malicious reports not checked")
	}
}

func writeTrust(w io.Writer, trust lockfile.Trust) {
	fmt.Fprintln(w)
	switch trust.Status {
	case lockfile.StatusTrusted:
		fmt.Fprintln(w, "verdict  trusted (under active policy)")
	case lockfile.StatusUntrusted:
		reason := strings.Join(trust.Reasons, ", ")
		if reason == "" {
			reason = "failed policy"
		}
		fmt.Fprintf(w, "verdict  untrusted (%s)\n", reason)
	default:
		reason := strings.Join(trust.Reasons, ", ")
		if reason == "" {
			reason = "incomplete evidence"
		}
		fmt.Fprintf(w, "verdict  unknown (%s)\n", reason)
	}
}

func writeCheck(w io.Writer, ok bool, good, bad string) {
	if ok {
		fmt.Fprintf(w, "✓ %s\n", good)
		return
	}
	fmt.Fprintf(w, "✗ %s\n", bad)
}

func summarizeCaps(caps lockfile.CapabilityEvidence) string {
	var parts []string
	addBool := func(name string, v *bool) {
		if v != nil && *v {
			parts = append(parts, name)
		}
	}
	addBool("network", caps.Network)
	if caps.Filesystem == lockfile.FilesystemRead || caps.Filesystem == lockfile.FilesystemWrite {
		parts = append(parts, "filesystem:"+string(caps.Filesystem))
	}
	addBool("environment", caps.Environment)
	addBool("shell", caps.Shell)
	addBool("native_code", caps.NativeCode)
	addBool("install_scripts", caps.InstallScripts)
	if len(parts) == 0 {
		return "none observed"
	}
	return strings.Join(parts, ", ")
}

func match(art lockfile.Artifact, query string) bool {
	q := strings.ToLower(query)
	if strings.EqualFold(art.Subject.Name, query) {
		return true
	}
	if strings.EqualFold(art.SubjectID(), query) {
		return true
	}
	if strings.EqualFold(art.ArtifactID(), query) {
		return true
	}
	// Allow "react@19.2.0" without ecosystem prefix.
	if strings.Contains(q, "@") {
		name, ver, ok := strings.Cut(query, "@")
		if ok && strings.EqualFold(art.Subject.Name, name) && art.Version == ver {
			return true
		}
	}
	return false
}
