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
	Vulnerabilities []cdxVuln   `json:"vulnerabilities"`
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
// with only a vulnerabilities list, whose analysis carries the decision. Affected packages
// are named by purl.
func WriteCycloneDX(w io.Writer, lock lockfile.Document, accepted exceptions.Document, opts Options) error {
	if strings.TrimSpace(opts.Author) == "" {
		return errors.New("a VEX document needs an author")
	}
	stmts := statements(lock, accepted, opts.clock())
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
	for _, s := range stmts {
		v := cdxVuln{ID: s.Vulnerability, Source: cdxSource{Name: "OSV", URL: advisoryURL(s.Vulnerability)}}
		if s.NotAffected {
			v.Analysis = cdxAnalysis{State: "not_affected", Justification: cdxJustification[s.Justification], Detail: s.Detail}
		} else {
			v.Analysis = cdxAnalysis{State: "exploitable", Response: []string{"will_not_fix"}, Detail: s.Detail}
		}
		for _, p := range s.Products {
			v.Affects = append(v.Affects, cdxAffects{Ref: p})
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
		id = append(id, s.Vulnerability, v.Analysis.State, strings.Join(s.Products, ","))
	}
	doc.SerialNumber = "urn:uuid:" + documentID(id...)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
