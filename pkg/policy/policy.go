package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	RequireNoVulnerabilities bool `json:"require_no_vulnerabilities" yaml:"require_no_vulnerabilities"`
	RequireDigest            bool `json:"require_digest" yaml:"require_digest"`
	RequireProvenance        bool `json:"require_provenance" yaml:"require_provenance"`
	RequireSignature         bool `json:"require_signature" yaml:"require_signature"`
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
	if doc.Version == 0 {
		doc.Version = SchemaVersion
	}
	doc.Network.Mode = doc.Network.ResolvedMode()
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum), nil
}
