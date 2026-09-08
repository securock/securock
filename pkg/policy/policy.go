package policy

type Document struct {
	Version int   `json:"version" yaml:"version"`
	Rules   Rules `json:"rules" yaml:"rules"`
}

type Rules struct {
	RequireNoVulnerabilities bool `json:"require_no_vulnerabilities" yaml:"require_no_vulnerabilities"`
	RequireDigest            bool `json:"require_digest" yaml:"require_digest"`
	RequireProvenance        bool `json:"require_provenance" yaml:"require_provenance"`
	RequireSignature         bool `json:"require_signature" yaml:"require_signature"`
}

func Default() Document {
	return Document{
		Version: 1,
		Rules: Rules{
			RequireNoVulnerabilities: true,
		},
	}
}
