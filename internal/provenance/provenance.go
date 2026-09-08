package provenance

import "github.com/securock/securock/pkg/lockfile"

func State() lockfile.EvidenceState {
	return lockfile.EvidenceUnknown
}
