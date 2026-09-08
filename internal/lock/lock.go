package lock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/decode"
	"github.com/securock/securock/pkg/lockfile"
	"gopkg.in/yaml.v3"
)

const DefaultName = "securock.lock"

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

func Read(path string) (lockfile.Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return lockfile.Document{}, err
	}

	var doc lockfile.Document
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		err = decode.JSON(raw, &doc)
	default:
		err = decode.YAML(raw, &doc)
	}
	if err != nil {
		return lockfile.Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	lockfile.Canonicalize(&doc)
	if err := lockfile.Validate(doc); err != nil {
		return lockfile.Document{}, fmt.Errorf("validate %s: %w", path, err)
	}
	return doc, nil
}
