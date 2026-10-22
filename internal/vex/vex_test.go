package vex_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/internal/vex"
	"github.com/securock/securock/pkg/exceptions"
	"github.com/securock/securock/pkg/lockfile"
)

var stamp = time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC)

func artifact(eco, name, version string, vulns ...string) lockfile.Artifact {
	a := lockfile.Artifact{Subject: lockfile.Subject{Ecosystem: eco, Name: name}, Version: version}
	a.Evidence.Vulnerabilities.State = lockfile.VulnChecked
	for _, id := range vulns {
		a.Evidence.Vulnerabilities.Items = append(a.Evidence.Vulnerabilities.Items, lockfile.Vulnerability{ID: id})
	}
	return a
}

func lock() lockfile.Document {
	return lockfile.Document{Artifacts: []lockfile.Artifact{
		artifact("npm", "lodash", "4.17.20", "GHSA-1", "GHSA-2"),
		artifact("npm", "lodash", "3.0.0", "GHSA-1"),
		artifact("npm", "react", "19.2.0"),
		artifact("url", "https://esm.sh/x", "", "GHSA-1"),
	}}
}

func ex(id, subject, justification string) exceptions.Exception {
	return exceptions.Exception{
		ID: id, Subject: subject, Reason: "tracked in ENG-1", Approver: "alice",
		Expires: "2999-12-31", Justification: justification,
	}
}

func accepted(list ...exceptions.Exception) exceptions.Document {
	return exceptions.Document{Version: 1, Exceptions: list}
}

func openvex(t *testing.T, doc exceptions.Document, opts vex.Options) (out struct {
	Context    string `json:"@context"`
	ID         string `json:"@id"`
	Author     string
	Timestamp  string
	Statements []struct {
		Vulnerability struct {
			ID   string `json:"@id"`
			Name string
		}
		Products []struct {
			ID string `json:"@id"`
		}
		Status          string
		Justification   string
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
	}
}) {
	t.Helper()
	var buf bytes.Buffer
	if opts.Author == "" {
		opts.Author = "Security Team"
	}
	opts.Time = stamp
	if err := vex.WriteOpenVEX(&buf, lock(), doc, opts); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenVEXAcceptedRiskIsAffected(t *testing.T) {
	out := openvex(t, accepted(ex("known-vulnerability:GHSA-2", "", "")), vex.Options{})
	if out.Context != "https://openvex.dev/ns/v0.2.0" || out.Author != "Security Team" || out.Timestamp != "2026-06-15T09:30:00Z" {
		t.Fatalf("header: %+v", out)
	}
	if !strings.HasPrefix(out.ID, "https://securock.dev/vex/") {
		t.Fatalf("id = %s", out.ID)
	}
	if len(out.Statements) != 1 {
		t.Fatalf("statements = %+v", out.Statements)
	}
	s := out.Statements[0]
	if s.Vulnerability.Name != "GHSA-2" || s.Vulnerability.ID != "https://osv.dev/vulnerability/GHSA-2" {
		t.Fatalf("vulnerability = %+v", s.Vulnerability)
	}
	if len(s.Products) != 1 || s.Products[0].ID != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("products = %+v", s.Products)
	}
	if s.Status != "affected" || s.Justification != "" || s.ImpactStatement != "" {
		t.Fatalf("status = %+v", s)
	}
	if s.ActionStatement != "Risk accepted by alice until 2999-12-31: tracked in ENG-1" {
		t.Fatalf("action = %q", s.ActionStatement)
	}
}

func TestOpenVEXJustificationIsNotAffected(t *testing.T) {
	out := openvex(t, accepted(ex("known-vulnerability:GHSA-2", "npm:lodash@4.17.20", "vulnerable_code_not_in_execute_path")), vex.Options{})
	s := out.Statements[0]
	if s.Status != "not_affected" || s.Justification != "vulnerable_code_not_in_execute_path" || s.ImpactStatement != "tracked in ENG-1" || s.ActionStatement != "" {
		t.Fatalf("statement = %+v", s)
	}
}

func TestOpenVEXProductsFollowTheSubject(t *testing.T) {
	// Without a subject the exception covers every package with the advisory that has a purl.
	all := openvex(t, accepted(ex("known-vulnerability:GHSA-1", "", "")), vex.Options{})
	if len(all.Statements[0].Products) != 2 || all.Statements[0].Products[0].ID != "pkg:npm/lodash@3.0.0" || all.Statements[0].Products[1].ID != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("products = %+v (url imports have no purl and are left out)", all.Statements[0].Products)
	}
	// A package name covers every version; a full artifact covers one.
	byName := openvex(t, accepted(ex("known-vulnerability:GHSA-1", "npm:lodash", "")), vex.Options{})
	if len(byName.Statements[0].Products) != 2 {
		t.Fatalf("products = %+v", byName.Statements[0].Products)
	}
	one := openvex(t, accepted(ex("known-vulnerability:GHSA-1", "npm:lodash@3.0.0", "")), vex.Options{})
	if len(one.Statements[0].Products) != 1 || one.Statements[0].Products[0].ID != "pkg:npm/lodash@3.0.0" {
		t.Fatalf("products = %+v", one.Statements[0].Products)
	}
}

func TestOpenVEXLeavesOutWhatDoesNotApply(t *testing.T) {
	expired := ex("known-vulnerability:GHSA-1", "", "")
	expired.Expires = "2020-01-01"
	out := openvex(t, accepted(
		ex("known-vulnerability:GHSA-2", "", ""), // the one that applies
		expired,
		ex("known-vulnerability:GHSA-9", "", ""),          // not in the lockfile
		ex("known-vulnerability:GHSA-2", "npm:react", ""), // react does not have it
		ex("capability:network", "", ""),                  // not a vulnerability
		ex("missing-digest", "", ""),
	), vex.Options{})
	if len(out.Statements) != 1 || out.Statements[0].Vulnerability.Name != "GHSA-2" {
		t.Fatalf("statements = %+v", out.Statements)
	}
}

func TestOpenVEXIsDeterministicAndOrdered(t *testing.T) {
	doc := accepted(ex("known-vulnerability:GHSA-2", "", ""), ex("known-vulnerability:GHSA-1", "", ""))
	reversed := accepted(doc.Exceptions[1], doc.Exceptions[0])
	a := openvex(t, doc, vex.Options{})
	b := openvex(t, reversed, vex.Options{})
	if a.ID != b.ID || a.Statements[0].Vulnerability.Name != "GHSA-1" || a.Statements[1].Vulnerability.Name != "GHSA-2" {
		t.Fatalf("order or id differ: %s vs %s, %+v", a.ID, b.ID, a.Statements)
	}
	other := openvex(t, doc, vex.Options{Author: "Someone Else"})
	if other.ID == a.ID {
		t.Fatal("a different author must give a different id")
	}
}

func TestNowDecidesWhichExceptionsAreActive(t *testing.T) {
	e := ex("known-vulnerability:GHSA-2", "", "")
	e.Expires = "2026-06-30"
	var buf bytes.Buffer
	opts := vex.Options{Author: "a", Time: stamp, Now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	if err := vex.WriteOpenVEX(&buf, lock(), accepted(e), opts); !errors.Is(err, vex.ErrNothingToExport) {
		t.Fatalf("an expired exception must not be exported: %v\n%s", err, buf.String())
	}
}

func TestVEXNeedsAnAuthor(t *testing.T) {
	var buf bytes.Buffer
	if err := vex.WriteOpenVEX(&buf, lock(), accepted(), vex.Options{Time: stamp}); err == nil {
		t.Fatal("expected an error")
	}
	if err := vex.WriteCycloneDX(&buf, lock(), accepted(), vex.Options{Author: "  ", Time: stamp}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCycloneDXVEX(t *testing.T) {
	var buf bytes.Buffer
	doc := accepted(
		ex("known-vulnerability:GHSA-1", "npm:lodash@3.0.0", "inline_mitigations_already_exist"),
		ex("known-vulnerability:GHSA-2", "", ""),
	)
	if err := vex.WriteCycloneDX(&buf, lock(), doc, vex.Options{Author: "Security Team", Time: stamp, ToolVersion: "1.2.3"}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		BOMFormat    string
		SpecVersion  string
		SerialNumber string
		Metadata     struct {
			Timestamp string
			Authors   []struct{ Name string }
		}
		Vulnerabilities []struct {
			ID       string
			Analysis struct {
				State         string
				Justification string
				Response      []string
				Detail        string
			}
			Affects []struct{ Ref string }
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.BOMFormat != "CycloneDX" || out.SpecVersion != "1.6" || !strings.HasPrefix(out.SerialNumber, "urn:uuid:") ||
		out.Metadata.Timestamp != "2026-06-15T09:30:00Z" || out.Metadata.Authors[0].Name != "Security Team" {
		t.Fatalf("header: %s", buf.String())
	}
	if len(out.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %+v", out.Vulnerabilities)
	}
	notAffected, affected := out.Vulnerabilities[0], out.Vulnerabilities[1]
	if notAffected.ID != "GHSA-1" || notAffected.Analysis.State != "not_affected" ||
		notAffected.Analysis.Justification != "protected_by_mitigating_control" || notAffected.Analysis.Detail != "tracked in ENG-1" ||
		len(notAffected.Affects) != 1 || notAffected.Affects[0].Ref != "pkg:npm/lodash@3.0.0" {
		t.Fatalf("not affected = %+v", notAffected)
	}
	if affected.ID != "GHSA-2" || affected.Analysis.State != "exploitable" || len(affected.Analysis.Response) != 1 ||
		affected.Analysis.Response[0] != "will_not_fix" || !strings.HasPrefix(affected.Analysis.Detail, "Risk accepted by alice") {
		t.Fatalf("affected = %+v", affected)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
