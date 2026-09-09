package schemas

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const idPrefix = "https://securock.dev/schema/"

//go:embed *.json
var files embed.FS

func Validate(schemaFile string, instance []byte) error {
	c := jsonschema.NewCompiler()
	ents, err := fs.ReadDir(files, ".")
	if err != nil {
		return err
	}
	for _, ent := range ents {
		raw, err := files.ReadFile(ent.Name())
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", ent.Name(), err)
		}
		if err := c.AddResource(idPrefix+ent.Name(), doc); err != nil {
			return fmt.Errorf("%s: %w", ent.Name(), err)
		}
	}
	sch, err := c.Compile(idPrefix + schemaFile)
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(instance, &v); err != nil {
		return err
	}
	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("%s: %w", schemaFile, err)
	}
	return nil
}
