// Package vex turns accepted vulnerabilities into a VEX (Vulnerability Exploitability
// eXchange) document, so what a team decided about an advisory can travel with the SBOM.
//
// Only known-vulnerability exceptions become statements. An exception with a
// justification says the product is not affected; one without says it is affected and the
// risk is accepted for now, which is VEX "affected" with an action statement.
package vex

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/securock/securock/internal/sbom"
	"github.com/securock/securock/pkg/exceptions"
	"github.com/securock/securock/pkg/lockfile"
)

// ErrNothingToExport means no active exception names an advisory present in the lockfile.
// An OpenVEX document must have at least one statement, and an empty VEX says nothing.
var ErrNothingToExport = errors.New("no accepted vulnerability applies to the packages in securock.lock; record one with securock accept")

const (
	SpecOpenVEX   = "openvex"
	SpecCycloneDX = "cyclonedx"
)

type Options struct {
	// Author names whoever vouches for the statements. VEX requires one.
	Author string
	// Time stamps the document and each statement.
	Time time.Time
	// Now decides which exceptions are still active; the zero value uses Time.
	Now         time.Time
	ToolVersion string
}

// product is a package a statement is about, named by its purl.
type product struct {
	PURL    string
	Name    string
	Version string
}

// statement is one decision about one advisory, across every package it applies to.
type statement struct {
	Vulnerability string
	Products      []product
	NotAffected   bool
	Justification string
	// Detail is the impact statement for not_affected, the action statement otherwise.
	Detail string
}

// statements finds each active exception that names an advisory present in the lockfile.
// An exception with no matching package says nothing about this product, so it is left out.
func statements(lock lockfile.Document, doc exceptions.Document, now time.Time) []statement {
	var out []statement
	for _, e := range doc.Exceptions {
		vuln, ok := strings.CutPrefix(e.ID, exceptions.VulnerabilityPrefix)
		if !ok || e.Expired(now) {
			continue
		}
		products := map[string]product{}
		for _, a := range lock.Artifacts {
			purl := sbom.PURL(a)
			if purl == "" || !e.Matches(e.ID, a.ArtifactID()) || !hasVulnerability(a, vuln) {
				continue
			}
			products[purl] = product{PURL: purl, Name: a.Subject.Name, Version: a.Version}
		}
		if len(products) == 0 {
			continue
		}
		s := statement{Vulnerability: vuln, Products: sortedProducts(products)}
		if e.Justification != "" {
			s.NotAffected, s.Justification, s.Detail = true, e.Justification, e.Reason
		} else {
			s.Detail = actionStatement(e)
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Vulnerability != out[j].Vulnerability {
			return out[i].Vulnerability < out[j].Vulnerability
		}
		return productKey(out[i].Products) < productKey(out[j].Products)
	})
	return out
}

func hasVulnerability(a lockfile.Artifact, id string) bool {
	for _, v := range a.Evidence.Vulnerabilities.Items {
		if v.ID == id {
			return true
		}
	}
	return false
}

func actionStatement(e exceptions.Exception) string {
	by := ""
	if e.Approver != "" {
		by = " by " + e.Approver
	}
	return fmt.Sprintf("Risk accepted%s until %s: %s", by, e.Expires, e.Reason)
}

func sortedProducts(m map[string]product) []product {
	out := make([]product, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out
}

func productKey(ps []product) string {
	keys := make([]string, len(ps))
	for i, p := range ps {
		keys[i] = p.PURL
	}
	return strings.Join(keys, ",")
}

func (o Options) clock() time.Time {
	if !o.Now.IsZero() {
		return o.Now
	}
	return o.Time
}

func (o Options) stamp() string { return o.Time.UTC().Format("2006-01-02T15:04:05Z") }

// documentID is stable for a given set of statements, author, and time.
func documentID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s\n", len(p), p)
	}
	sum := h.Sum(nil)
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func advisoryURL(id string) string { return "https://osv.dev/vulnerability/" + id }
