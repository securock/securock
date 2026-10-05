package policy

import (
	"fmt"
	"slices"
)

var (
	changeActions = []ChangeAction{"", ActionAllow, ActionWarn, ActionReview, ActionDeny}
	capNames      = []string{"network", "filesystem", "environment", "shell", "native_code", "install_scripts"}
	fsMaximums    = []string{"", "none", "read", "write"}
)

func Validate(doc Document) error {
	if doc.Version != SchemaVersion {
		return fmt.Errorf("unsupported policy version %d", doc.Version)
	}
	switch doc.Network.ResolvedMode() {
	case ModePublicOnly, ModeOffline, ModeAllowAll:
	default:
		return fmt.Errorf("unknown network mode %q", doc.Network.Mode)
	}
	if err := validateEvidenceRule("provenance", doc.Rules.Provenance.Minimum); err != nil {
		return err
	}
	if err := validateEvidenceRule("signature", doc.Rules.Signature.Minimum); err != nil {
		return err
	}
	switch doc.Rules.Vulnerabilities.Allow {
	case "", "none":
	default:
		return fmt.Errorf("unknown vulnerabilities allow %q", doc.Rules.Vulnerabilities.Allow)
	}
	if err := validateCapabilityRule(doc.Rules.Capabilities); err != nil {
		return err
	}
	if err := validateOwnershipRule(doc.Rules.Ownership); err != nil {
		return err
	}
	return nil
}

func validateEvidenceRule(name, minimum string) error {
	switch minimum {
	case "", "present", "verified":
		return nil
	default:
		return fmt.Errorf("unknown %s minimum %q", name, minimum)
	}
}

func validateCapabilityRule(rule CapabilityRule) error {
	for _, name := range rule.Deny {
		if !slices.Contains(capNames, name) {
			return fmt.Errorf("unknown capability deny %q", name)
		}
	}
	if !slices.Contains(fsMaximums, rule.Filesystem.Maximum) {
		return fmt.Errorf("unknown filesystem maximum %q", rule.Filesystem.Maximum)
	}
	return nil
}

func validateOwnershipRule(rule OwnershipRule) error {
	for _, pair := range []struct {
		name   string
		action ChangeAction
	}{
		{"publisher_change", rule.PublisherChange},
		{"maintainer_added", rule.MaintainerAdded},
		{"maintainer_removed", rule.MaintainerRemoved},
	} {
		if !slices.Contains(changeActions, pair.action) {
			return fmt.Errorf("unknown ownership %s action %q", pair.name, pair.action)
		}
	}
	return nil
}

func ValidMode(mode Mode) bool {
	return slices.Contains([]Mode{ModePublicOnly, ModeOffline, ModeAllowAll}, mode)
}
