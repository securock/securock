package lockfile

const SchemaVersion = 2

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
	Kind      string `json:"kind,omitempty" yaml:"kind,omitempty"`
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
	Provenance      EvidenceState      `json:"provenance" yaml:"provenance"`
	Signature       EvidenceState      `json:"signature" yaml:"signature"`
	Vulnerabilities VulnEvidence       `json:"vulnerabilities" yaml:"vulnerabilities"`
	Malicious       MaliciousEvidence  `json:"malicious" yaml:"malicious"`
	Capabilities    CapabilityEvidence `json:"capabilities" yaml:"capabilities"`
	Behavior        BehaviorEvidence   `json:"behavior" yaml:"behavior"`
	Ownership       OwnershipEvidence  `json:"ownership" yaml:"ownership"`
	Chain           ChainEvidence      `json:"chain" yaml:"chain"`
}

type VulnEvidence struct {
	State VulnState       `json:"state" yaml:"state"`
	Items []Vulnerability `json:"items,omitempty" yaml:"items,omitempty"`
}

type Vulnerability struct {
	ID string `json:"id" yaml:"id"`
}

// MaliciousEvidence records OpenSSF Malicious Packages / OSV MAL-* reports.
// It is separate from VulnerabilityEvidence: malware is not a CVE.
type MaliciousEvidence struct {
	State   VulnState          `json:"state" yaml:"state"`
	Reports []MaliciousReport  `json:"reports,omitempty" yaml:"reports,omitempty"`
}

type MaliciousReport struct {
	ID string `json:"id" yaml:"id"`
}

type CapState string

const (
	CapUnknown CapState = "unknown"
	CapChecked CapState = "checked"
)

type FilesystemAccess string

const (
	FilesystemNone  FilesystemAccess = "none"
	FilesystemRead  FilesystemAccess = "read"
	FilesystemWrite FilesystemAccess = "write"
)

type ChainEvidence struct {
	State    EvidenceState `json:"state" yaml:"state"`
	Source   string        `json:"source,omitempty" yaml:"source,omitempty"`
	Commit   string        `json:"commit,omitempty" yaml:"commit,omitempty"`
	Builder  string        `json:"builder,omitempty" yaml:"builder,omitempty"`
	Workflow string        `json:"workflow,omitempty" yaml:"workflow,omitempty"`
}

// CapabilityEvidence records observed package capabilities.
// When State is CapUnknown, capability fields are omitted.
// Boolean fields use pointers so false is distinct from unchecked.
type CapabilityEvidence struct {
	State          CapState         `json:"state" yaml:"state"`
	Network        *bool            `json:"network,omitempty" yaml:"network,omitempty"`
	Filesystem     FilesystemAccess `json:"filesystem,omitempty" yaml:"filesystem,omitempty"`
	Environment    *bool            `json:"environment,omitempty" yaml:"environment,omitempty"`
	Shell          *bool            `json:"shell,omitempty" yaml:"shell,omitempty"`
	NativeCode     *bool            `json:"native_code,omitempty" yaml:"native_code,omitempty"`
	InstallScripts *bool            `json:"install_scripts,omitempty" yaml:"install_scripts,omitempty"`
}

// BehaviorEvidence records finer-grained observed behavior for drift detection.
type BehaviorEvidence struct {
	State       CapState       `json:"state" yaml:"state"`
	Network     []string       `json:"network,omitempty" yaml:"network,omitempty"`
	Files       *BehaviorFiles `json:"files,omitempty" yaml:"files,omitempty"`
	Commands    []string       `json:"commands,omitempty" yaml:"commands,omitempty"`
	Environment []string       `json:"environment,omitempty" yaml:"environment,omitempty"`
}

type BehaviorFiles struct {
	Read  []string `json:"read,omitempty" yaml:"read,omitempty"`
	Write []string `json:"write,omitempty" yaml:"write,omitempty"`
}

type OwnershipEvidence struct {
	State       CapState `json:"state" yaml:"state"`
	Publisher   string   `json:"publisher,omitempty" yaml:"publisher,omitempty"`
	Maintainers []string `json:"maintainers,omitempty" yaml:"maintainers,omitempty"`
}

type Trust struct {
	Status  Status   `json:"status" yaml:"status"`
	Reasons []string `json:"reasons,omitempty" yaml:"reasons,omitempty"`
}

func Bool(v bool) *bool { return &v }

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
