package vex

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/securock/securock/pkg/exceptions"
	"github.com/securock/securock/pkg/lockfile"
)

type openVEX struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Tooling    string             `json:"tooling,omitempty"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability   openVEXVulnerability `json:"vulnerability"`
	Timestamp       string               `json:"timestamp"`
	Products        []openVEXProduct     `json:"products"`
	Status          string               `json:"status"`
	Justification   string               `json:"justification,omitempty"`
	ImpactStatement string               `json:"impact_statement,omitempty"`
	ActionStatement string               `json:"action_statement,omitempty"`
}

type openVEXVulnerability struct {
	ID   string `json:"@id"`
	Name string `json:"name"`
}

type openVEXProduct struct {
	ID string `json:"@id"`
}

// WriteOpenVEX writes the accepted vulnerabilities as an OpenVEX 0.2.0 document.
func WriteOpenVEX(w io.Writer, lock lockfile.Document, accepted exceptions.Document, opts Options) error {
	if strings.TrimSpace(opts.Author) == "" {
		return errors.New("a VEX document needs an author")
	}
	stmts := statements(lock, accepted, opts.clock())
	if len(stmts) == 0 {
		return ErrNothingToExport
	}
	doc := openVEX{
		Context:    "https://openvex.dev/ns/v0.2.0",
		Author:     opts.Author,
		Timestamp:  opts.stamp(),
		Version:    1,
		Tooling:    "securock " + opts.ToolVersion,
		Statements: make([]openVEXStatement, 0, len(stmts)),
	}
	id := []string{opts.Author, opts.stamp()}
	for _, s := range stmts {
		st := openVEXStatement{
			Vulnerability: openVEXVulnerability{ID: advisoryURL(s.Vulnerability), Name: s.Vulnerability},
			Timestamp:     opts.stamp(),
		}
		for _, p := range s.Products {
			st.Products = append(st.Products, openVEXProduct{ID: p.PURL})
		}
		if s.NotAffected {
			st.Status, st.Justification, st.ImpactStatement = "not_affected", s.Justification, s.Detail
		} else {
			st.Status, st.ActionStatement = "affected", s.Detail
		}
		doc.Statements = append(doc.Statements, st)
		id = append(id, s.Vulnerability, st.Status, productKey(s.Products))
	}
	doc.ID = "https://securock.dev/vex/" + documentID(id...)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
