package lock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	var (
		raw []byte
		err error
	)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		raw, err = json.MarshalIndent(doc, "", "  ")
		if err == nil {
			raw = append(raw, '\n')
		}
	default:
		raw, err = yaml.Marshal(doc)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func Read(path string) (lockfile.Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return lockfile.Document{}, err
	}

	var doc lockfile.Document
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		err = json.Unmarshal(raw, &doc)
	default:
		err = yaml.Unmarshal(raw, &doc)
	}
	if err != nil {
		return lockfile.Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc, nil
}
