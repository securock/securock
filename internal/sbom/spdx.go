package sbom

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/securock/securock/internal/license"
	"github.com/securock/securock/pkg/lockfile"
)

type spdxDoc struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string           `json:"SPDXID"`
	Name             string           `json:"name"`
	VersionInfo      string           `json:"versionInfo,omitempty"`
	DownloadLocation string           `json:"downloadLocation"`
	FilesAnalyzed    bool             `json:"filesAnalyzed"`
	LicenseConcluded string           `json:"licenseConcluded"`
	LicenseDeclared  string           `json:"licenseDeclared"`
	CopyrightText    string           `json:"copyrightText"`
	Checksums        []spdxChecksum   `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternal   `json:"externalRefs,omitempty"`
	Annotations      []spdxAnnotation `json:"annotations,omitempty"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type spdxExternal struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxAnnotation struct {
	Annotator string `json:"annotator"`
	Date      string `json:"annotationDate"`
	Type      string `json:"annotationType"`
	Comment   string `json:"comment"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

const (
	spdxAnnotator = "Tool: securock"
	noAssertion   = "NOASSERTION"
)

var spdxIDInvalid = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// WriteSPDX writes the lock as an SPDX 2.3 JSON document. Trust evidence is carried as
// annotations whose comment is "securock:key=value".
func WriteSPDX(w io.Writer, doc lockfile.Document, opts Options) error {
	created := opts.Created
	if created.IsZero() {
		created = time.Unix(0, 0)
	}
	stamp := created.UTC().Format("2006-01-02T15:04:05Z")

	comps := components(doc)
	pkgs := make([]spdxPackage, 0, len(comps))
	rels := make([]spdxRelationship, 0, len(comps))
	ids := make([]string, 0, len(comps))
	for _, c := range comps {
		id := spdxID(c.ID)
		ids = append(ids, c.ID)
		p := spdxPackage{
			SPDXID:           id,
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: noAssertion,
			LicenseConcluded: noAssertion,
			LicenseDeclared:  noAssertion,
			CopyrightText:    noAssertion,
		}
		// SPDX only accepts known identifiers here; any other text stays in the
		// securock:license annotation and the declared license is not asserted.
		if license.IsSPDX(c.License) {
			p.LicenseDeclared = license.NormalizeExpression(c.License)
		}
		for _, h := range c.Hashes {
			p.Checksums = append(p.Checksums, spdxChecksum{Algorithm: strings.ToUpper(h.Alg), Value: h.Hex})
		}
		if c.PURL != "" {
			p.ExternalRefs = []spdxExternal{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: c.PURL}}
		}
		for _, prop := range c.Properties {
			p.Annotations = append(p.Annotations, spdxAnnotation{
				Annotator: spdxAnnotator, Date: stamp, Type: "OTHER", Comment: prop.Name + "=" + prop.Value,
			})
		}
		pkgs = append(pkgs, p)
		rels = append(rels, spdxRelationship{Element: "SPDXRef-DOCUMENT", Type: "DESCRIBES", Related: id})
	}

	out := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "securock-sbom",
		DocumentNamespace: "https://securock.dev/spdx/" + uuid(contentID(append(ids, doc.Policy.Digest)...)),
		CreationInfo:      spdxCreationInfo{Created: stamp, Creators: []string{spdxAnnotator + "-" + opts.ToolVersion}},
		Packages:          pkgs,
		Relationships:     rels,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// spdxID builds a unique, valid SPDX identifier: the readable part is sanitized and the
// hash suffix keeps names that sanitize to the same text apart.
func spdxID(artifactID string) string {
	sum := contentID(artifactID)
	return "SPDXRef-Package-" + strings.Trim(spdxIDInvalid.ReplaceAllString(artifactID, "-"), "-") + "-" + hex.EncodeToString(sum[:4])
}

// digestFromSPDX is the inverse of the checksum mapping, giving the normalized "alg:hex" form.
func digestFromSPDX(c spdxChecksum) string {
	return strings.ToLower(c.Algorithm) + ":" + strings.ToLower(c.Value)
}
