package vex

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/securock/securock/pkg/exceptions"
	"github.com/securock/securock/pkg/lockfile"
)

type cdxVEX struct {
	BOMFormat       string      `json:"bomFormat"`
	SpecVersion     string      `json:"specVersion"`
	SerialNumber    string      `json:"serialNumber"`
	Version         int         `json:"version"`
	Metadata        cdxMetadata `json:"metadata"`
	Components      []cdxComp   `json:"components,omitempty"`
	Vulnerabilities []cdxVuln   `json:"vulnerabilities"`
}

// cdxComp declares a package the vulnerabilities refer to, with its purl as bom-ref, so
// every reference in the document resolves within it.
type cdxComp struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxTools     `json:"tools"`
	Authors   []cdxContact `json:"authors"`
}

type cdxTools struct {
	Components []cdxTool `json:"components"`
}

type cdxTool struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxContact struct {
	Name string `json:"name"`
}

type cdxVuln struct {
	ID       string       `json:"id"`
	Source   cdxSource    `json:"source"`
	Analysis cdxAnalysis  `json:"analysis"`
	Affects  []cdxAffects `json:"affects"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

// cdxJustification maps an OpenVEX justification to the closest CycloneDX one.
var cdxJustification = map[string]string{
	"component_not_present":                             "code_not_present",
	"vulnerable_code_not_present":                       "code_not_present",
	"vulnerable_code_not_in_execute_path":               "code_not_reachable",
	"vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
	"inline_mitigations_already_exist":                  "protected_by_mitigating_control",
}

// WriteCycloneDX writes the accepted vulnerabilities as a CycloneDX 1.6 VEX: a document
// whose vulnerabilities carry the decision in their analysis. Affected packages are
// declared as components, with the purl as bom-ref, and referenced by it.
func WriteCycloneDX(w io.Writer, lock lockfile.Document, accepted exceptions.Document, opts Options) error {
	if strings.TrimSpace(opts.Author) == "" {
		return errors.New("a VEX document needs an author")
	}
	stmts := statements(lock, accepted, opts.clock())
	if len(stmts) == 0 {
		return ErrNothingToExport
	}
	doc := cdxVEX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: opts.stamp(),
			Tools:     cdxTools{Components: []cdxTool{{Type: "application", Name: "securock", Version: opts.ToolVersion}}},
			Authors:   []cdxContact{{Name: opts.Author}},
		},
		Vulnerabilities: make([]cdxVuln, 0, len(stmts)),
	}
	id := []string{opts.Author, opts.stamp()}
	declared := map[string]bool{}
	for _, s := range stmts {
		for _, p := range s.Products {
			if !declared[p.PURL] {
				declared[p.PURL] = true
				doc.Components = append(doc.Components, cdxComp{BOMRef: p.PURL, Type: "library", Name: p.Name, Version: p.Version, PURL: p.PURL})
			}
		}
		v := cdxVuln{ID: s.Vulnerability, Source: cdxSource{Name: "OSV", URL: advisoryURL(s.Vulnerability)}}
		if s.NotAffected {
			v.Analysis = cdxAnalysis{State: "not_affected", Justification: cdxJustification[s.Justification], Detail: s.Detail}
		} else {
			v.Analysis = cdxAnalysis{State: "exploitable", Response: []string{"will_not_fix"}, Detail: s.Detail}
		}
		for _, p := range s.Products {
			v.Affects = append(v.Affects, cdxAffects{Ref: p.PURL})
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
		id = append(id, s.Vulnerability, v.Analysis.State, productKey(s.Products))
	}
	doc.SerialNumber = "urn:uuid:" + documentID(id...)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
