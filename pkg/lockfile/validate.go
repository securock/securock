package lockfile

import (
	"fmt"
	"slices"
)

var (
	ecosystems = []string{"npm", "jsr", "url", "cargo", "go", "pypi", "packagist"}
	resolvers  = []string{"npm", "pnpm", "yarn", "bun", "deno", "cargo", "go", "uv", "poetry", "pdm", "composer"}
	statuses   = []Status{StatusTrusted, StatusUntrusted, StatusUnknown}
	evidence   = []EvidenceState{EvidenceUnknown, EvidenceMissing, EvidencePresent, EvidenceVerified}
	vulnStates = []VulnState{VulnUnknown, VulnChecked}
)

func Validate(doc Document) error {
	if doc.Version != SchemaVersion {
		return fmt.Errorf("unsupported lockfile version %d", doc.Version)
	}
	for _, eco := range doc.Source.Ecosystems {
		if !slices.Contains(ecosystems, eco) {
			return fmt.Errorf("unknown ecosystem %q", eco)
		}
	}
	for _, res := range doc.Source.Resolvers {
		if !slices.Contains(resolvers, res) {
			return fmt.Errorf("unknown resolver %q", res)
		}
	}
	for i, art := range doc.Artifacts {
		if err := validateArtifact(art); err != nil {
			return fmt.Errorf("artifacts[%d]: %w", i, err)
		}
	}
	return nil
}

func validateArtifact(art Artifact) error {
	if !slices.Contains(ecosystems, art.Subject.Ecosystem) {
		return fmt.Errorf("unknown ecosystem %q", art.Subject.Ecosystem)
	}
	if art.Subject.Name == "" {
		return fmt.Errorf("missing subject name")
	}
	if art.Version == "" {
		return fmt.Errorf("missing version")
	}
	if art.Source.Resolver != "" && !slices.Contains(resolvers, art.Source.Resolver) {
		return fmt.Errorf("unknown resolver %q", art.Source.Resolver)
	}
	if !slices.Contains(evidence, art.Evidence.Provenance) {
		return fmt.Errorf("unknown provenance state %q", art.Evidence.Provenance)
	}
	if !slices.Contains(evidence, art.Evidence.Signature) {
		return fmt.Errorf("unknown signature state %q", art.Evidence.Signature)
	}
	if !slices.Contains(vulnStates, art.Evidence.Vulnerabilities.State) {
		return fmt.Errorf("unknown vulnerability state %q", art.Evidence.Vulnerabilities.State)
	}
	for _, v := range art.Evidence.Vulnerabilities.Items {
		if v.ID == "" {
			return fmt.Errorf("missing vulnerability id")
		}
	}
	if !slices.Contains(statuses, art.Trust.Status) {
		return fmt.Errorf("unknown trust status %q", art.Trust.Status)
	}
	return nil
}
