package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	SpecCycloneDX = "cyclonedx"
	SpecSPDX      = "spdx"
)

// Entry is one package read back from an SBOM, whichever format it came in.
type Entry struct {
	Name    string
	Version string
	PURL    string
	// Digest is the securock:digest property when present, otherwise the first standard hash.
	Digest string
	Props  map[string][]string
}

// Document is the part of an SBOM that verification compares against the lock.
type Document struct {
	Spec         string
	PolicyDigest string
	Entries      []Entry
}

// Parse reads a CycloneDX or SPDX JSON document.
func Parse(raw []byte) (Document, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Document{}, fmt.Errorf("sbom is not valid JSON: %w", err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(raw)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-"):
		return parseSPDX(raw)
	default:
		return Document{}, errors.New("unrecognized SBOM: expected CycloneDX or SPDX JSON")
	}
}

func parseCycloneDX(raw []byte) (Document, error) {
	var bom cdxBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return Document{}, fmt.Errorf("invalid CycloneDX document: %w", err)
	}
	doc := Document{Spec: SpecCycloneDX}
	for _, p := range bom.Metadata.Properties {
		if p.Name == PropPolicy {
			doc.PolicyDigest = p.Value
		}
	}
	for _, c := range bom.Components {
		e := Entry{Name: c.Name, Version: c.Version, PURL: c.PURL, Props: map[string][]string{}}
		for _, p := range c.Properties {
			e.Props[p.Name] = append(e.Props[p.Name], p.Value)
		}
		e.Digest = first(e.Props[PropDigest])
		if e.Digest == "" && len(c.Hashes) > 0 {
			e.Digest = digestFromCDX(c.Hashes[0])
		}
		doc.Entries = append(doc.Entries, e)
	}
	return doc, nil
}

func parseSPDX(raw []byte) (Document, error) {
	var spdx spdxDoc
	if err := json.Unmarshal(raw, &spdx); err != nil {
		return Document{}, fmt.Errorf("invalid SPDX document: %w", err)
	}
	doc := Document{Spec: SpecSPDX}
	for _, p := range spdx.Packages {
		e := Entry{Name: p.Name, Version: p.VersionInfo, Props: map[string][]string{}}
		for _, ref := range p.ExternalRefs {
			if ref.Type == "purl" && e.PURL == "" {
				e.PURL = ref.Locator
			}
		}
		for _, a := range p.Annotations {
			if name, value, ok := strings.Cut(a.Comment, "="); ok && strings.HasPrefix(name, PropertyPrefix) {
				e.Props[name] = append(e.Props[name], value)
			}
		}
		e.Digest = first(e.Props[PropDigest])
		if e.Digest == "" && len(p.Checksums) > 0 {
			e.Digest = digestFromSPDX(p.Checksums[0])
		}
		doc.Entries = append(doc.Entries, e)
	}
	return doc, nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
