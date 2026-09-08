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
	return nil
}

func ValidMode(mode Mode) bool {
	return slices.Contains([]Mode{ModePublicOnly, ModeOffline, ModeAllowAll}, mode)
}
