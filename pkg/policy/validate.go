package policy

import (
	"fmt"
	"slices"
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

func ValidMode(mode Mode) bool {
	return slices.Contains([]Mode{ModePublicOnly, ModeOffline, ModeAllowAll}, mode)
}
