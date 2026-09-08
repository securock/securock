package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/pkg/policy"
	"gopkg.in/yaml.v3"
)

func Load(path string) (policy.Document, error) {
	if path == "" {
		return policy.Default(), nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return policy.Document{}, err
	}

	var doc policy.Document
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		err = json.Unmarshal(raw, &doc)
	default:
		err = yaml.Unmarshal(raw, &doc)
	}
	if err != nil {
		return policy.Document{}, fmt.Errorf("parse policy: %w", err)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}
