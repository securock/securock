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
	EvidenceMissing  EvidenceState = "missing"
	EvidencePresent  EvidenceState = "present"
	EvidenceVerified EvidenceState = "verified"
)

func (s EvidenceState) Present() bool {
	return s == EvidencePresent || s == EvidenceVerified
}

type VulnState string

const (
	VulnUnknown VulnState = "unknown"
	VulnChecked VulnState = "checked"
)

type Document struct {
	Version   int        `json:"version" yaml:"version"`
	Source    Source     `json:"source,omitempty" yaml:"source,omitempty"`
	Policy    PolicyRef  `json:"policy,omitempty" yaml:"policy,omitempty"`
	Artifacts []Artifact `json:"artifacts" yaml:"artifacts"`
}

type PolicyRef struct {
	Digest string `json:"digest,omitempty" yaml:"digest,omitempty"`
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
	Resolver  string `json:"resolver,omitempty" yaml:"resolver,omitempty"`
	Registry  string `json:"registry,omitempty" yaml:"registry,omitempty"`
	Artifact  string `json:"artifact,omitempty" yaml:"artifact,omitempty"`
	Requested string `json:"requested,omitempty" yaml:"requested,omitempty"`
	Resolved  string `json:"resolved,omitempty" yaml:"resolved,omitempty"`
}

type Artifact struct {
	Subject  Subject        `json:"subject" yaml:"subject"`
	Version  string         `json:"version,omitempty" yaml:"version,omitempty"`
	Filename string         `json:"filename,omitempty" yaml:"filename,omitempty"`
	Digest   string         `json:"digest,omitempty" yaml:"digest,omitempty"`
	Source   ArtifactSource `json:"source,omitempty" yaml:"source,omitempty"`
	Evidence Evidence       `json:"evidence" yaml:"evidence"`
	Trust    Trust          `json:"trust" yaml:"trust"`
}

type Evidence struct {
	Provenance      EvidenceState `json:"provenance" yaml:"provenance"`
	Signature       EvidenceState `json:"signature" yaml:"signature"`
	Vulnerabilities VulnEvidence  `json:"vulnerabilities" yaml:"vulnerabilities"`
}

type VulnEvidence struct {
	State VulnState       `json:"state" yaml:"state"`
	Items []Vulnerability `json:"items,omitempty" yaml:"items,omitempty"`
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
	id := a.SubjectID()
	if a.Version != "" {
		id += "@" + a.Version
	}
	if a.Filename != "" {
		return id + "#" + a.Filename
	}
	return id
}

func (a Artifact) Identity() string {
	return a.SubjectID()
}
