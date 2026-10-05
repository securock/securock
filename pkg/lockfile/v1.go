package lockfile

// V1Document mirrors the securock.lock schema shipped in Securock v0.1.0.
// It exists so version-1 files can be decoded strictly before migration.
type V1Document struct {
	Version   int          `json:"version" yaml:"version"`
	Source    Source       `json:"source,omitempty" yaml:"source,omitempty"`
	Policy    PolicyRef    `json:"policy,omitempty" yaml:"policy,omitempty"`
	Artifacts []V1Artifact `json:"artifacts" yaml:"artifacts"`
}

// V1Artifact is one artifact entry from a v0.1.0 lockfile.
type V1Artifact struct {
	Subject  Subject        `json:"subject" yaml:"subject"`
	Version  string         `json:"version,omitempty" yaml:"version,omitempty"`
	Filename string         `json:"filename,omitempty" yaml:"filename,omitempty"`
	Digest   string         `json:"digest,omitempty" yaml:"digest,omitempty"`
	Source   ArtifactSource `json:"source,omitempty" yaml:"source,omitempty"`
	Evidence V1Evidence     `json:"evidence" yaml:"evidence"`
	Trust    Trust          `json:"trust" yaml:"trust"`
}

// V1Evidence is the evidence block from Securock v0.1.0: provenance,
// signature, and vulnerabilities only.
type V1Evidence struct {
	Provenance      EvidenceState `json:"provenance" yaml:"provenance"`
	Signature       EvidenceState `json:"signature" yaml:"signature"`
	Vulnerabilities VulnEvidence  `json:"vulnerabilities" yaml:"vulnerabilities"`
}
