package lockfile

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
	Version   int        `json:"version" yaml:"version"`
	Source    Source     `json:"source,omitempty" yaml:"source,omitempty"`
	Artifacts []Artifact `json:"artifacts" yaml:"artifacts"`
}

type Source struct {
	Ecosystems []string `json:"ecosystems,omitempty" yaml:"ecosystems,omitempty"`
	Resolvers  []string `json:"resolvers,omitempty" yaml:"resolvers,omitempty"`
}

type Subject struct {
	Ecosystem string `json:"ecosystem" yaml:"ecosystem"`
	Name      string `json:"name" yaml:"name"`
}

type ArtifactSource struct {
	Resolver string `json:"resolver,omitempty" yaml:"resolver,omitempty"`
	Registry string `json:"registry,omitempty" yaml:"registry,omitempty"`
}

type Artifact struct {
	Subject  Subject        `json:"subject" yaml:"subject"`
	Version  string         `json:"version" yaml:"version"`
	Digest   string         `json:"digest,omitempty" yaml:"digest,omitempty"`
	Source   ArtifactSource `json:"source,omitempty" yaml:"source,omitempty"`
	Evidence Evidence       `json:"evidence" yaml:"evidence"`
	Trust    Trust          `json:"trust" yaml:"trust"`
}

type Evidence struct {
	Provenance      EvidenceState   `json:"provenance" yaml:"provenance"`
	Signature       EvidenceState   `json:"signature" yaml:"signature"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
}

type Vulnerability struct {
	ID string `json:"id" yaml:"id"`
}

type Trust struct {
	Status  Status   `json:"status" yaml:"status"`
	Reasons []string `json:"reasons,omitempty" yaml:"reasons,omitempty"`
}

func (s Subject) ID() string {
	return s.Ecosystem + ":" + s.Name
}

func (a Artifact) SubjectID() string {
	return a.Subject.ID()
}

func (a Artifact) ArtifactID() string {
	return a.SubjectID() + "@" + a.Version
}

func (a Artifact) Identity() string {
	return a.SubjectID()
}
