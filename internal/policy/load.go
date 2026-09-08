package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/decode"
	"github.com/securock/securock/pkg/policy"
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
		err = decode.JSON(raw, &doc)
	default:
		err = decode.YAML(raw, &doc)
	}
	if err != nil {
		return policy.Document{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := policy.Validate(doc); err != nil {
		return policy.Document{}, fmt.Errorf("validate policy: %w", err)
	}
	return doc, nil
}
