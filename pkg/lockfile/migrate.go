package lockfile

import "fmt"

// MigrateV1 converts a strictly-decoded v0.1.0 document to SchemaVersion.
//
// digest, source, provenance, signature, and vulnerabilities are kept.
// malicious, capabilities, behavior, ownership, and chain become unknown.
// trust is always unknown — v1 "trusted" is not carried forward.
func MigrateV1(v1 V1Document) (Document, error) {
	if v1.Version != 1 {
		return Document{}, fmt.Errorf("expected lockfile version 1, got %d", v1.Version)
	}
	out := Document{
		Version:   SchemaVersion,
		Source:    v1.Source,
		Policy:    v1.Policy,
		Artifacts: make([]Artifact, len(v1.Artifacts)),
	}
	for i, art := range v1.Artifacts {
		out.Artifacts[i] = Artifact{
			Subject:  art.Subject,
			Version:  art.Version,
			Filename: art.Filename,
			Digest:   art.Digest,
			Source:   art.Source,
			Evidence: Evidence{
				Provenance:      art.Evidence.Provenance,
				Signature:       art.Evidence.Signature,
				Vulnerabilities: art.Evidence.Vulnerabilities,
				Malicious:       MaliciousEvidence{State: VulnUnknown},
				Capabilities:    CapabilityEvidence{State: CapUnknown},
				Behavior:        BehaviorEvidence{State: CapUnknown},
				Ownership:       OwnershipEvidence{State: CapUnknown},
				Chain:           ChainEvidence{State: EvidenceUnknown},
			},
			Trust: Trust{Status: StatusUnknown},
		}
	}
	return out, nil
}
