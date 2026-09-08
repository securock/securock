package lockfile

import "time"

const SchemaVersion = 1

type Status string

const (
	StatusTrusted   Status = "trusted"
	StatusUntrusted Status = "untrusted"
	StatusUnknown   Status = "unknown"
)

type EvidenceState string

const (
	EvidenceUnknown  EvidenceState = "unknown"
	EvidenceVerified EvidenceState = "verified"
	EvidenceMissing  EvidenceState = "missing"
)

type Document struct {
	Version     int        `json:"version" yaml:"version"`
	GeneratedAt time.Time  `json:"generated_at" yaml:"generated_at"`
	Source      Source     `json:"source,omitempty" yaml:"source,omitempty"`
	Artifacts   []Artifact `json:"artifacts" yaml:"artifacts"`
}

type Source struct {
	Path       string   `json:"path,omitempty" yaml:"path,omitempty"`
	Ecosystems []string `json:"ecosystems,omitempty" yaml:"ecosystems,omitempty"`
}

type Artifact struct {
	Ecosystem string   `json:"ecosystem" yaml:"ecosystem"`
	Name      string   `json:"name" yaml:"name"`
	Version   string   `json:"version" yaml:"version"`
	Digest    string   `json:"digest,omitempty" yaml:"digest,omitempty"`
	Evidence  Evidence `json:"evidence" yaml:"evidence"`
	Trust     Trust    `json:"trust" yaml:"trust"`
}

type Evidence struct {
	Provenance      EvidenceState   `json:"provenance" yaml:"provenance"`
	Signature       EvidenceState   `json:"signature" yaml:"signature"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
}

type Vulnerability struct {
	ID       string `json:"id" yaml:"id"`
	Modified string `json:"modified,omitempty" yaml:"modified,omitempty"`
}

type Trust struct {
	Status  Status   `json:"status" yaml:"status"`
	Reasons []string `json:"reasons,omitempty" yaml:"reasons,omitempty"`
}

func (a Artifact) Identity() string {
	return a.Ecosystem + ":" + a.Name + "@" + a.Version
}
