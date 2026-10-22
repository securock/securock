package sbom

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

type cdxBOM struct {
	BOMFormat       string         `json:"bomFormat"`
	SpecVersion     string         `json:"specVersion"`
	SerialNumber    string         `json:"serialNumber"`
	Version         int            `json:"version"`
	Metadata        cdxMetadata    `json:"metadata"`
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp  string        `json:"timestamp,omitempty"`
	Tools      cdxTools      `json:"tools"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxTools struct {
	Components []cdxTool `json:"components"`
}

type cdxTool struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxComponent struct {
	BOMRef     string        `json:"bom-ref"`
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxVuln struct {
	ID      string       `json:"id"`
	Source  cdxVulnSrc   `json:"source"`
	Affects []cdxAffects `json:"affects"`
}

type cdxVulnSrc struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

// WriteCycloneDX writes the lock as a CycloneDX 1.6 JSON document. Trust evidence is
// carried as securock:* component properties.
func WriteCycloneDX(w io.Writer, doc lockfile.Document, opts Options) error {
	comps := components(doc)
	out := make([]cdxComponent, 0, len(comps))
	for _, c := range comps {
		cc := cdxComponent{BOMRef: c.ID, Type: "library", Name: c.Name, Version: c.Version, PURL: c.PURL}
		for _, h := range c.Hashes {
			cc.Hashes = append(cc.Hashes, cdxHash{Alg: cdxAlg(h.Alg), Content: h.Hex})
		}
		for _, p := range c.Properties {
			cc.Properties = append(cc.Properties, cdxProperty{p.Name, p.Value})
		}
		out = append(out, cc)
	}

	var vulns []cdxVuln
	byID := vulnerabilities(doc)
	for _, id := range sortedKeys(byID) {
		v := cdxVuln{ID: id, Source: cdxVulnSrc{Name: "OSV", URL: "https://osv.dev/vulnerability/" + id}}
		for _, ref := range byID[id] {
			v.Affects = append(v.Affects, cdxAffects{Ref: ref})
		}
		vulns = append(vulns, v)
	}

	body, err := json.Marshal(out)
	if err != nil {
		return err
	}
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid(contentID(string(body), doc.Policy.Digest)),
		Version:      1,
		Metadata: cdxMetadata{
			Tools: cdxTools{Components: []cdxTool{{Type: "application", Name: "securock", Version: opts.ToolVersion}}},
		},
		Components:      out,
		Vulnerabilities: vulns,
	}
	if !opts.Created.IsZero() {
		bom.Metadata.Timestamp = opts.Created.UTC().Format("2006-01-02T15:04:05Z")
	}
	if doc.Policy.Digest != "" {
		bom.Metadata.Properties = []cdxProperty{{PropPolicy, doc.Policy.Digest}}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

func cdxAlg(alg string) string {
	switch alg {
	case "sha1":
		return "SHA-1"
	case "sha256":
		return "SHA-256"
	case "sha384":
		return "SHA-384"
	default:
		return "SHA-512"
	}
}

// digestFromCDX is the inverse of cdxAlg, giving the normalized "alg:hex" form.
func digestFromCDX(h cdxHash) string {
	alg := strings.ToLower(strings.ReplaceAll(h.Alg, "-", ""))
	return alg + ":" + strings.ToLower(h.Content)
}
