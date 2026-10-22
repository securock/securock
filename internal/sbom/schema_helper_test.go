package sbom_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// officialSchemas compiles the vendored CycloneDX, SPDX, and OpenVEX schemas.
func officialSchemas(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	dir := filepath.Join("testdata", "schemas")
	c := jsonschema.NewCompiler()
	for file, id := range map[string]string{
		"bom-1.6.schema.json":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"spdx.schema.json":         "http://cyclonedx.org/schema/spdx.schema.json",
		"jsf-0.82.schema.json":     "http://cyclonedx.org/schema/jsf-0.82.schema.json",
		"spdx-schema.json":         "http://spdx.org/rdf/terms/2.3",
		"openvex_json_schema.json": "https://github.com/openvex/spec/openvex_json_schema_0.2.0.json",
	} {
		f, err := os.Open(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// validateAgainst checks a generated document against one of the vendored schemas.
func validateAgainst(t *testing.T, c *jsonschema.Compiler, schemaID string, raw []byte) {
	t.Helper()
	sch, err := c.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("not valid against %s:\n%v\n%s", schemaID, err, raw)
	}
}
