package vex_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/securock/securock/internal/vex"
	"github.com/securock/securock/pkg/exceptions"
)

func TestVEXIsValidAgainstTheOfficialSchemas(t *testing.T) {
	c := officialSchemas(t)
	docs := map[string]exceptions.Document{
		"mixed": accepted(
			ex("known-vulnerability:GHSA-1", "npm:lodash@3.0.0", "vulnerable_code_not_in_execute_path"),
			ex("known-vulnerability:GHSA-2", "", ""),
			ex("known-vulnerability:GHSA-1", "npm:lodash@4.17.20", "inline_mitigations_already_exist"),
		),
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			opts := vex.Options{Author: "Security Team", Time: stamp, ToolVersion: "1.2.3"}
			var openvex, cdx bytes.Buffer
			if err := vex.WriteOpenVEX(&openvex, lock(), doc, opts); err != nil {
				t.Fatal(err)
			}
			if err := vex.WriteCycloneDX(&cdx, lock(), doc, opts); err != nil {
				t.Fatal(err)
			}
			validateAgainst(t, c, "https://github.com/openvex/spec/openvex_json_schema_0.2.0.json", openvex.Bytes())
			validateAgainst(t, c, "http://cyclonedx.org/schema/bom-1.6.schema.json", cdx.Bytes())
		})
	}
}

func TestCycloneDXVEXReferencesResolveWithinTheDocument(t *testing.T) {
	var buf bytes.Buffer
	doc := accepted(ex("known-vulnerability:GHSA-1", "", ""))
	if err := vex.WriteCycloneDX(&buf, lock(), doc, vex.Options{Author: "a", Time: stamp}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
			PURL   string
		}
		Vulnerabilities []struct {
			Affects []struct{ Ref string }
		}
	}
	if err := jsonUnmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, c := range out.Components {
		declared[c.BOMRef] = c.BOMRef == c.PURL
	}
	for _, v := range out.Vulnerabilities {
		for _, a := range v.Affects {
			if !declared[a.Ref] {
				t.Fatalf("affects %q is not declared as a component: %+v", a.Ref, out.Components)
			}
		}
	}
	if len(out.Components) != 2 {
		t.Fatalf("components = %+v", out.Components)
	}
}

func TestNothingToExportIsAnError(t *testing.T) {
	expired := ex("known-vulnerability:GHSA-1", "", "")
	expired.Expires = "2020-01-01"
	for name, doc := range map[string]exceptions.Document{
		"no exceptions":       accepted(),
		"expired":             accepted(expired),
		"not in the lock":     accepted(ex("known-vulnerability:GHSA-9", "", "")),
		"not a vulnerability": accepted(ex("capability:network", "", "")),
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			opts := vex.Options{Author: "a", Time: stamp}
			if err := vex.WriteOpenVEX(&buf, lock(), doc, opts); !errors.Is(err, vex.ErrNothingToExport) {
				t.Fatalf("openvex: %v", err)
			}
			if err := vex.WriteCycloneDX(&buf, lock(), doc, opts); !errors.Is(err, vex.ErrNothingToExport) {
				t.Fatalf("cyclonedx: %v", err)
			}
			if buf.Len() != 0 {
				t.Fatalf("nothing should be written: %s", buf.String())
			}
		})
	}
}
