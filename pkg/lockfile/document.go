package lockfile

// SchemaVersion is the current lockfile version. Version 3 added optional release health,
// advisory severity and fixed versions, and reachability fields. A file written at version 3
// is refused by older releases, which decode strictly, instead of being half read.
const SchemaVersion = 3

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

	// Scope and Dependencies are recorded only by scans run with --reachability.
	// Scope says how the package enters the project; empty means the lockfile does not say.
	Scope Scope `json:"scope,omitempty" yaml:"scope,omitempty"`
	// Dependencies lists the artifact IDs this package depends on directly.
	Dependencies []string `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
}

type Scope string

const (
	ScopeRuntime  Scope = "runtime"
	ScopeDev      Scope = "dev"
	ScopeOptional Scope = "optional"
)

// Reachability says whether a vulnerable package is part of what runs in production.
type Reachability string

const (
	ReachUnknown Reachability = "unknown"
	ReachYes     Reachability = "yes"
	ReachNo      Reachability = "no"
)

type Evidence struct {
	Provenance      EvidenceState      `json:"provenance" yaml:"provenance"`
	Signature       EvidenceState      `json:"signature" yaml:"signature"`
	Vulnerabilities VulnEvidence       `json:"vulnerabilities" yaml:"vulnerabilities"`
	Malicious       MaliciousEvidence  `json:"malicious" yaml:"malicious"`
	Capabilities    CapabilityEvidence `json:"capabilities" yaml:"capabilities"`
	Behavior        BehaviorEvidence   `json:"behavior" yaml:"behavior"`
	Ownership       OwnershipEvidence  `json:"ownership" yaml:"ownership"`
	Chain           ChainEvidence      `json:"chain" yaml:"chain"`
	// Health is nil when the registry was not asked or did not answer, so a lockfile
	// never claims a package is healthy without having looked.
	Health *HealthEvidence `json:"health,omitempty" yaml:"health,omitempty"`
}

type VulnEvidence struct {
	State VulnState       `json:"state" yaml:"state"`
	Items []Vulnerability `json:"items,omitempty" yaml:"items,omitempty"`
}

type Vulnerability struct {
	ID string `json:"id" yaml:"id"`

	// Reachable and Via are recorded only by scans run with --reachability.
	// Via is the dependency path from a runtime package to this one, when it is not direct.
	Reachable Reachability `json:"reachable,omitempty" yaml:"reachable,omitempty"`
	Via       []string     `json:"via,omitempty" yaml:"via,omitempty"`

	// Severity and Fixed come from the advisory record. Severity is empty when the advisory
	// carries no rating securock can read; Fixed lists the versions that fix it for this
	// package, oldest first.
	Severity VulnSeverity `json:"severity,omitempty" yaml:"severity,omitempty"`
	Fixed    []string     `json:"fixed,omitempty" yaml:"fixed,omitempty"`
}

type VulnSeverity string

const (
	SeverityLow      VulnSeverity = "low"
	SeverityMedium   VulnSeverity = "medium"
	SeverityHigh     VulnSeverity = "high"
	SeverityCritical VulnSeverity = "critical"
)

// MaliciousEvidence records OpenSSF Malicious Packages / OSV MAL-* reports.
// It is separate from VulnerabilityEvidence: malware is not a CVE.
type MaliciousEvidence struct {
	State   VulnState         `json:"state" yaml:"state"`
	Reports []MaliciousReport `json:"reports,omitempty" yaml:"reports,omitempty"`
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
	State         EvidenceState `json:"state" yaml:"state"`
	Source        string        `json:"source,omitempty" yaml:"source,omitempty"`
	Commit        string        `json:"commit,omitempty" yaml:"commit,omitempty"`
	Ref           string        `json:"ref,omitempty" yaml:"ref,omitempty"`
	Builder       string        `json:"builder,omitempty" yaml:"builder,omitempty"`
	Workflow      string        `json:"workflow,omitempty" yaml:"workflow,omitempty"`
	PredicateType string        `json:"predicate_type,omitempty" yaml:"predicate_type,omitempty"`
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

// HealthEvidence records what the registry says about the release itself.
type HealthEvidence struct {
	// Released is the day this version was published, as YYYY-MM-DD. Empty when unknown.
	Released string `json:"released,omitempty" yaml:"released,omitempty"`
	// Deprecated is the maintainer's deprecation message, or "yanked" with its reason
	// on PyPI. Empty means the registry reports the release as supported.
	Deprecated string `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
	// License is the declared license, preferably an SPDX expression.
	License string `json:"license,omitempty" yaml:"license,omitempty"`
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
