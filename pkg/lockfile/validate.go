package lockfile

import (
	"fmt"
	"slices"
)

var (
	ecosystems  = []string{"npm", "jsr", "url", "cargo", "go", "pypi", "packagist", "rubygems", "nuget", "swift", "pub", "hex", "maven"}
	resolvers   = []string{"npm", "pnpm", "yarn", "bun", "deno", "cargo", "go", "uv", "poetry", "pdm", "composer", "bundler", "nuget", "swiftpm", "pub", "mix", "gradle"}
	statuses    = []Status{StatusTrusted, StatusUntrusted, StatusUnknown}
	evidence    = []EvidenceState{EvidenceUnknown, EvidenceMissing, EvidencePresent, EvidenceVerified}
	vulnStates  = []VulnState{VulnUnknown, VulnChecked}
	capStates   = []CapState{CapUnknown, CapChecked}
	filesystems = []FilesystemAccess{"", FilesystemNone, FilesystemRead, FilesystemWrite}
	sourceKinds = []string{"", "registry", "workspace", "git", "file", "url"}
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
	if art.Version == "" && art.Subject.Ecosystem != "url" {
		return fmt.Errorf("missing version")
	}
	if art.Source.Resolver != "" && !slices.Contains(resolvers, art.Source.Resolver) {
		return fmt.Errorf("unknown resolver %q", art.Source.Resolver)
	}
	if !slices.Contains(sourceKinds, art.Source.Kind) {
		return fmt.Errorf("unknown source kind %q", art.Source.Kind)
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
	if art.Evidence.Malicious.State == "" {
		return fmt.Errorf("missing malicious state")
	}
	if !slices.Contains(vulnStates, art.Evidence.Malicious.State) {
		return fmt.Errorf("unknown malicious state %q", art.Evidence.Malicious.State)
	}
	for _, r := range art.Evidence.Malicious.Reports {
		if r.ID == "" {
			return fmt.Errorf("missing malicious report id")
		}
	}
	if art.Evidence.Capabilities.State == "" {
		return fmt.Errorf("missing capabilities state")
	}
	if !slices.Contains(capStates, art.Evidence.Capabilities.State) {
		return fmt.Errorf("unknown capabilities state %q", art.Evidence.Capabilities.State)
	}
	if !slices.Contains(filesystems, art.Evidence.Capabilities.Filesystem) {
		return fmt.Errorf("unknown filesystem capability %q", art.Evidence.Capabilities.Filesystem)
	}
	if art.Evidence.Behavior.State == "" {
		return fmt.Errorf("missing behavior state")
	}
	if !slices.Contains(capStates, art.Evidence.Behavior.State) {
		return fmt.Errorf("unknown behavior state %q", art.Evidence.Behavior.State)
	}
	if art.Evidence.Ownership.State == "" {
		return fmt.Errorf("missing ownership state")
	}
	if !slices.Contains(capStates, art.Evidence.Ownership.State) {
		return fmt.Errorf("unknown ownership state %q", art.Evidence.Ownership.State)
	}
	for _, name := range art.Evidence.Ownership.Maintainers {
		if name == "" {
			return fmt.Errorf("missing maintainer name")
		}
	}
	if art.Evidence.Chain.State == "" {
		return fmt.Errorf("missing chain state")
	}
	if !slices.Contains(evidence, art.Evidence.Chain.State) {
		return fmt.Errorf("unknown chain state %q", art.Evidence.Chain.State)
	}
	if !slices.Contains(statuses, art.Trust.Status) {
		return fmt.Errorf("unknown trust status %q", art.Trust.Status)
	}
	return nil
}
