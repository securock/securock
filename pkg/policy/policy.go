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
	RequireNoVulnerabilities bool         `json:"require_no_vulnerabilities" yaml:"require_no_vulnerabilities"`
	RequireDigest            bool         `json:"require_digest" yaml:"require_digest"`
	RequireProvenance        bool         `json:"require_provenance" yaml:"require_provenance"`
	RequireSignature         bool         `json:"require_signature" yaml:"require_signature"`
	Provenance               EvidenceRule `json:"provenance,omitempty" yaml:"provenance,omitempty"`
	Signature                EvidenceRule `json:"signature,omitempty" yaml:"signature,omitempty"`
}

type EvidenceRule struct {
	Minimum string `json:"minimum,omitempty" yaml:"minimum,omitempty"`
}

func Default() Document {
	return Document{
		Version: SchemaVersion,
		Network: Network{Mode: ModePublicOnly},
		Rules: Rules{
			RequireNoVulnerabilities: true,
		},
	}
}

func (n Network) ResolvedMode() Mode {
	if n.Mode == "" {
		return ModePublicOnly
	}
	return n.Mode
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
	Rules   canonicalRules    `json:"rules"`
}

type canonicalNetwork struct {
	Mode       Mode                `json:"mode"`
	Registries map[string][]string `json:"registries,omitempty"`
}

type canonicalRules struct {
	RequireNoVulnerabilities bool               `json:"require_no_vulnerabilities,omitempty"`
	RequireDigest            bool               `json:"require_digest,omitempty"`
	RequireProvenance        bool               `json:"require_provenance,omitempty"`
	RequireSignature         bool               `json:"require_signature,omitempty"`
	Provenance               *canonicalEvidence `json:"provenance,omitempty"`
	Signature                *canonicalEvidence `json:"signature,omitempty"`
}

type canonicalEvidence struct {
	Minimum string `json:"minimum,omitempty"`
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
			RequireDigest:            doc.Rules.RequireDigest,
			RequireProvenance:        doc.Rules.RequireProvenance,
			RequireSignature:         doc.Rules.RequireSignature,
			Provenance:               canonicalEvidenceRule(doc.Rules.Provenance),
			Signature:                canonicalEvidenceRule(doc.Rules.Signature),
		},
	}
}

func canonicalEvidenceRule(rule EvidenceRule) *canonicalEvidence {
	if rule.Minimum == "" {
		return nil
	}
	return &canonicalEvidence{Minimum: rule.Minimum}
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
