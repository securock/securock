package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/decode"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/policy"
)

func Load(path string) (policy.Document, error) {
	return LoadWithProfile(path, "")
}

// LoadWithProfile loads a policy file or a built-in profile.
// path and profile are mutually exclusive when both are non-empty.
func LoadWithProfile(path, profile string) (policy.Document, error) {
	if path != "" && profile != "" {
		return policy.Document{}, fmt.Errorf("--policy and --profile are mutually exclusive")
	}
	if path == "" {
		doc, err := policy.Profile(profile)
		if err != nil {
			return policy.Document{}, err
		}
		if err := policy.Validate(doc); err != nil {
			return policy.Document{}, fmt.Errorf("validate policy: %w", err)
		}
		return doc, nil
	}

	raw, err := core.ReadFileLimit(path, 1<<20)
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
