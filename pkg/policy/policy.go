package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
)

const SchemaVersion = 1

type Mode string

const (
	ModePublicOnly Mode = "public-only"
	ModeOffline    Mode = "offline"
	ModeAllowAll   Mode = "allow-all"
)

type ChangeAction string

const (
	ActionAllow  ChangeAction = "allow"
	ActionWarn   ChangeAction = "warn"
	ActionReview ChangeAction = "review"
	ActionDeny   ChangeAction = "deny"
)

type Document struct {
	Version int     `json:"version" yaml:"version"`
	Network Network `json:"network,omitempty" yaml:"network,omitempty"`
	Rules   Rules   `json:"rules" yaml:"rules"`
}

type Network struct {
	Mode       Mode                `json:"mode,omitempty" yaml:"mode,omitempty"`
	Registries map[string][]string `json:"registries,omitempty" yaml:"registries,omitempty"`
}

type Rules struct {
	RequireNoVulnerabilities bool              `json:"require_no_vulnerabilities" yaml:"require_no_vulnerabilities"`
	RequireNoMalicious       bool              `json:"require_no_malicious" yaml:"require_no_malicious"`
	RequireDigest            bool              `json:"require_digest" yaml:"require_digest"`
	RequireProvenance        bool              `json:"require_provenance" yaml:"require_provenance"`
	RequireSignature         bool              `json:"require_signature" yaml:"require_signature"`
	Provenance               EvidenceRule      `json:"provenance,omitempty" yaml:"provenance,omitempty"`
	Signature                EvidenceRule      `json:"signature,omitempty" yaml:"signature,omitempty"`
	Vulnerabilities          VulnerabilityRule `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
	Malicious                MaliciousRule     `json:"malicious,omitempty" yaml:"malicious,omitempty"`
	Capabilities             CapabilityRule    `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Ownership                OwnershipRule     `json:"ownership,omitempty" yaml:"ownership,omitempty"`
}

type EvidenceRule struct {
	Minimum string `json:"minimum,omitempty" yaml:"minimum,omitempty"`
}

// VulnerabilityRule is an optional structured form of vulnerability policy.
// allow: "none" is equivalent to require_no_vulnerabilities: true.
type VulnerabilityRule struct {
	Allow string `json:"allow,omitempty" yaml:"allow,omitempty"`
}

// MaliciousRule is an optional structured form of malware policy.
// allow: "none" is equivalent to require_no_malicious: true.
type MaliciousRule struct {
	Allow string `json:"allow,omitempty" yaml:"allow,omitempty"`
}

type CapabilityRule struct {
	Deny       []string       `json:"deny,omitempty" yaml:"deny,omitempty"`
	Filesystem FilesystemRule `json:"filesystem,omitempty" yaml:"filesystem,omitempty"`
}

type FilesystemRule struct {
	Maximum string `json:"maximum,omitempty" yaml:"maximum,omitempty"`
}

type OwnershipRule struct {
	PublisherChange   ChangeAction `json:"publisher_change,omitempty" yaml:"publisher_change,omitempty"`
	MaintainerAdded   ChangeAction `json:"maintainer_added,omitempty" yaml:"maintainer_added,omitempty"`
	MaintainerRemoved ChangeAction `json:"maintainer_removed,omitempty" yaml:"maintainer_removed,omitempty"`
}

func Default() Document {
	return Document{
		Version: SchemaVersion,
		Network: Network{Mode: ModePublicOnly},
		Rules: Rules{
			RequireNoVulnerabilities: true,
			RequireNoMalicious:       true,
		},
	}
}

func (n Network) ResolvedMode() Mode {
	if n.Mode == "" {
		return ModePublicOnly
	}
	return n.Mode
}

func (r Rules) DenyVulnerabilities() bool {
	if r.RequireNoVulnerabilities {
		return true
	}
	return r.Vulnerabilities.Allow == "none"
}

func (r Rules) DenyMalicious() bool {
	if r.RequireNoMalicious {
		return true
	}
	return r.Malicious.Allow == "none"
}

func (a ChangeAction) Fails() bool {
	return a == ActionDeny || a == ActionReview
}

func (a ChangeAction) Reports() bool {
	return a == ActionWarn || a.Fails()
}

func (r OwnershipRule) Configured() bool {
	return r.PublisherChange != "" || r.MaintainerAdded != "" || r.MaintainerRemoved != ""
}

func (r CapabilityRule) Configured() bool {
	return len(r.Deny) > 0 || r.Filesystem.Maximum != ""
}

func Fingerprint(doc Document) (string, error) {
	raw, err := json.Marshal(canonical(doc))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum), nil
}

type canonicalDocument struct {
	Version int              `json:"version"`
	Network canonicalNetwork `json:"network"`
	Rules   canonicalRules   `json:"rules"`
}

type canonicalNetwork struct {
	Mode       Mode                `json:"mode"`
	Registries map[string][]string `json:"registries,omitempty"`
}

type canonicalRules struct {
	RequireNoVulnerabilities bool                `json:"require_no_vulnerabilities,omitempty"`
	RequireNoMalicious       bool                `json:"require_no_malicious,omitempty"`
	RequireDigest            bool                `json:"require_digest,omitempty"`
	RequireProvenance        bool                `json:"require_provenance,omitempty"`
	RequireSignature         bool                `json:"require_signature,omitempty"`
	Provenance               *canonicalEvidence  `json:"provenance,omitempty"`
	Signature                *canonicalEvidence  `json:"signature,omitempty"`
	Vulnerabilities          *canonicalVulnRule  `json:"vulnerabilities,omitempty"`
	Malicious                *canonicalVulnRule  `json:"malicious,omitempty"`
	Capabilities             *canonicalCapRule   `json:"capabilities,omitempty"`
	Ownership                *canonicalOwnerRule `json:"ownership,omitempty"`
}

type canonicalEvidence struct {
	Minimum string `json:"minimum,omitempty"`
}

type canonicalVulnRule struct {
	Allow string `json:"allow,omitempty"`
}

type canonicalCapRule struct {
	Deny       []string `json:"deny,omitempty"`
	Filesystem string   `json:"filesystem_maximum,omitempty"`
}

type canonicalOwnerRule struct {
	PublisherChange   ChangeAction `json:"publisher_change,omitempty"`
	MaintainerAdded   ChangeAction `json:"maintainer_added,omitempty"`
	MaintainerRemoved ChangeAction `json:"maintainer_removed,omitempty"`
}

func canonical(doc Document) canonicalDocument {
	if doc.Version == 0 {
		doc.Version = SchemaVersion
	}
	return canonicalDocument{
		Version: doc.Version,
		Network: canonicalNetwork{
			Mode:       doc.Network.ResolvedMode(),
			Registries: canonicalRegistries(doc.Network.Registries),
		},
		Rules: canonicalRules{
			RequireNoVulnerabilities: doc.Rules.RequireNoVulnerabilities,
			RequireNoMalicious:       doc.Rules.RequireNoMalicious,
			RequireDigest:            doc.Rules.RequireDigest,
			RequireProvenance:        doc.Rules.RequireProvenance,
			RequireSignature:         doc.Rules.RequireSignature,
			Provenance:               canonicalEvidenceRule(doc.Rules.Provenance),
			Signature:                canonicalEvidenceRule(doc.Rules.Signature),
			Vulnerabilities:          canonicalVuln(doc.Rules.Vulnerabilities),
			Malicious:                canonicalMalicious(doc.Rules.Malicious),
			Capabilities:             canonicalCapabilities(doc.Rules.Capabilities),
			Ownership:                canonicalOwnership(doc.Rules.Ownership),
		},
	}
}

func canonicalEvidenceRule(rule EvidenceRule) *canonicalEvidence {
	if rule.Minimum == "" {
		return nil
	}
	return &canonicalEvidence{Minimum: rule.Minimum}
}

func canonicalVuln(rule VulnerabilityRule) *canonicalVulnRule {
	if rule.Allow == "" {
		return nil
	}
	return &canonicalVulnRule{Allow: rule.Allow}
}

func canonicalMalicious(rule MaliciousRule) *canonicalVulnRule {
	if rule.Allow == "" {
		return nil
	}
	return &canonicalVulnRule{Allow: rule.Allow}
}

func canonicalCapabilities(rule CapabilityRule) *canonicalCapRule {
	if !rule.Configured() {
		return nil
	}
	deny := slices.Clone(rule.Deny)
	slices.Sort(deny)
	deny = slices.Compact(deny)
	return &canonicalCapRule{
		Deny:       deny,
		Filesystem: rule.Filesystem.Maximum,
	}
}

func canonicalOwnership(rule OwnershipRule) *canonicalOwnerRule {
	if !rule.Configured() {
		return nil
	}
	return &canonicalOwnerRule{
		PublisherChange:   rule.PublisherChange,
		MaintainerAdded:   rule.MaintainerAdded,
		MaintainerRemoved: rule.MaintainerRemoved,
	}
}

func canonicalRegistries(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for eco, urls := range in {
		copied := slices.Clone(urls)
		slices.Sort(copied)
		out[eco] = copied
	}
	return out
}
