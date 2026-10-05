package lock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/decode"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
	"gopkg.in/yaml.v3"
)

const DefaultName = "securock.lock"

// MigrationWarning is printed to stderr when a v1 lockfile is accepted
// in memory. The on-disk file is not modified.
const MigrationWarning = "securock.lock v1 migrated to v2 in memory; run 'securock lock' to accept the current trust state"

func Path(root, override string) string {
	if override != "" {
		if filepath.IsAbs(override) {
			return override
		}
		return filepath.Join(root, override)
	}
	return filepath.Join(root, DefaultName)
}

func Write(path string, doc lockfile.Document) error {
	raw, err := Encode(path, doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func Encode(path string, doc lockfile.Document) ([]byte, error) {
	lockfile.Canonicalize(&doc)
	if err := lockfile.Validate(doc); err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(raw, '\n'), nil
	default:
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
		if err := enc.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
}

// Read loads a lockfile. Version 1 documents are migrated to version 2 in
// memory only; the file on disk is never rewritten. migrated is true when
// a v1→v2 migration was applied.
func Read(path string) (doc lockfile.Document, migrated bool, err error) {
	raw, err := core.ReadFile(path)
	if err != nil {
		return lockfile.Document{}, false, err
	}
	return Parse(path, raw)
}

// Parse decodes lockfile bytes the same way Read does after loading a file.
func Parse(path string, raw []byte) (doc lockfile.Document, migrated bool, err error) {
	asJSON := strings.ToLower(filepath.Ext(path)) == ".json"

	version, err := peekVersion(raw, asJSON)
	if err != nil {
		return lockfile.Document{}, false, fmt.Errorf("parse %s: %w", path, err)
	}

	switch version {
	case 1:
		doc, err = parseV1(raw, asJSON)
		if err != nil {
			return lockfile.Document{}, false, fmt.Errorf("parse %s: %w", path, err)
		}
		migrated = true
	default:
		doc, err = parseCurrent(raw, asJSON)
		if err != nil {
			return lockfile.Document{}, false, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	lockfile.Canonicalize(&doc)
	if err := lockfile.Validate(doc); err != nil {
		return lockfile.Document{}, false, fmt.Errorf("validate %s: %w", path, err)
	}
	return doc, migrated, nil
}

func peekVersion(raw []byte, asJSON bool) (int, error) {
	var header struct {
		Version int `json:"version" yaml:"version"`
	}
	if asJSON {
		if err := json.Unmarshal(raw, &header); err != nil {
			return 0, err
		}
	} else if err := yaml.Unmarshal(raw, &header); err != nil {
		return 0, err
	}
	return header.Version, nil
}

func parseCurrent(raw []byte, asJSON bool) (lockfile.Document, error) {
	var doc lockfile.Document
	var err error
	if asJSON {
		err = decode.JSON(raw, &doc)
	} else {
		err = decode.YAML(raw, &doc)
	}
	return doc, err
}

func parseV1(raw []byte, asJSON bool) (lockfile.Document, error) {
	var v1 lockfile.V1Document
	var err error
	if asJSON {
		err = decode.JSON(raw, &v1)
	} else {
		err = decode.YAML(raw, &v1)
	}
	if err != nil {
		return lockfile.Document{}, err
	}
	return lockfile.MigrateV1(v1)
}
