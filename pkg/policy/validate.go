package policy

import (
	"fmt"
	"slices"
	"strings"
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
	if err := validateEvidenceRule("provenance", doc.Rules.Provenance); err != nil {
		return err
	}
	if err := validateEvidenceRule("signature", doc.Rules.Signature); err != nil {
		return err
	}
	if doc.Rules.Signature.OriginConfigured() {
		return fmt.Errorf("signature policy does not support provenance origin allowlists")
	}
	switch doc.Rules.Vulnerabilities.Allow {
	case "", "none":
	default:
		return fmt.Errorf("unknown vulnerabilities allow %q", doc.Rules.Vulnerabilities.Allow)
	}
	switch doc.Rules.Malicious.Allow {
	case "", "none":
	default:
		return fmt.Errorf("unknown malicious allow %q", doc.Rules.Malicious.Allow)
	}
	if err := validateCapabilityRule(doc.Rules.Capabilities); err != nil {
		return err
	}
	if err := validateOwnershipRule(doc.Rules.Ownership); err != nil {
		return err
	}
	return nil
}

func validateEvidenceRule(name string, rule EvidenceRule) error {
	switch rule.Minimum {
	case "", "present", "verified":
	default:
		return fmt.Errorf("unknown %s minimum %q", name, rule.Minimum)
	}
	for _, pair := range []struct {
		field string
		vals  []string
	}{
		{"allow_sources", rule.AllowSources},
		{"allow_builders", rule.AllowBuilders},
		{"allow_workflows", rule.AllowWorkflows},
		{"allow_refs", rule.AllowRefs},
		{"allow_predicate_types", rule.AllowPredicateTypes},
	} {
		for _, v := range pair.vals {
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("%s %s entry must not be empty", name, pair.field)
			}
		}
	}
	return nil
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
