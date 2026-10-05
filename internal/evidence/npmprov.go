package evidence

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
)

var (
	sigstoreOnce     sync.Once
	sigstoreVerifier *verify.Verifier
	sigstoreErr      error
)

func sigstorePublicVerifier() (*verify.Verifier, error) {
	sigstoreOnce.Do(func() {
		client, err := tuf.New(tuf.DefaultOptions())
		if err != nil {
			sigstoreErr = err
			return
		}
		trusted, err := root.GetTrustedRoot(client)
		if err != nil {
			sigstoreErr = err
			return
		}
		sigstoreVerifier, sigstoreErr = verify.NewVerifier(
			trusted,
			verify.WithSignedCertificateTimestamps(1),
			verify.WithTransparencyLog(1),
			verify.WithObserverTimestamps(1),
		)
	})
	return sigstoreVerifier, sigstoreErr
}

// verifyProvenanceBundle verifies an npm Sigstore bundle and returns the
// authenticated in-toto statement only when it is a provenance predicate
// bound to digest.
func verifyProvenanceBundle(bundleJSON []byte, digest string) (*verify.VerificationResult, bool) {
	if len(bundleJSON) == 0 || digest == "" {
		return nil, false
	}
	alg, hexDigest, ok := strings.Cut(digest, ":")
	if !ok || hexDigest == "" {
		return nil, false
	}
	rawDigest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, false
	}

	verifier, err := sigstorePublicVerifier()
	if err != nil || verifier == nil {
		return nil, false
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, false
	}

	identities := npmTrustedIdentities()
	if len(identities) == 0 {
		return nil, false
	}
	opts := make([]verify.PolicyOption, 0, len(identities))
	for _, id := range identities {
		opts = append(opts, verify.WithCertificateIdentity(id))
	}
	res, err := verifier.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest(strings.ToLower(alg), rawDigest),
		opts...,
	))
	if err != nil || res == nil || res.Statement == nil {
		return nil, false
	}
	if !isProvenance(res.Statement.GetPredicateType()) {
		return nil, false
	}
	return res, true
}

func npmTrustedIdentities() []verify.CertificateIdentity {
	var out []verify.CertificateIdentity
	for _, spec := range []struct {
		issuer   string
		sanRegex string
	}{
		{
			issuer:   "https://token.actions.githubusercontent.com",
			sanRegex: `^https://github.com/.+/.+/.github/workflows/.+`,
		},
		{
			issuer:   "https://gitlab.com",
			sanRegex: `^https://gitlab.com/.+`,
		},
	} {
		id, err := verify.NewShortCertificateIdentity(spec.issuer, "", "", spec.sanRegex)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out
}

func extractChainVerified(raw []byte, digest string) (lockfile.EvidenceState, lockfile.ChainEvidence) {
	state, chain := extractChain(raw)
	if state != lockfile.EvidencePresent {
		return state, chain
	}
	if digest == "" {
		return state, chain
	}
	digest = core.NormalizeDigest(digest)

	var parsed struct {
		Attestations []json.RawMessage `json:"attestations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return state, chain
	}
	for _, att := range parsed.Attestations {
		var envelope struct {
			Bundle json.RawMessage `json:"bundle"`
		}
		if err := json.Unmarshal(att, &envelope); err != nil {
			continue
		}
		if len(envelope.Bundle) == 0 {
			continue
		}
		res, ok := verifyProvenanceBundle(envelope.Bundle, digest)
		if !ok {
			continue
		}
		filled := chainFromVerifiedStatement(res)
		if filled.State != lockfile.EvidenceVerified {
			continue
		}
		return lockfile.EvidenceVerified, filled
	}
	return state, chain
}

func chainFromVerifiedStatement(res *verify.VerificationResult) lockfile.ChainEvidence {
	if res == nil || res.Statement == nil || res.Statement.Predicate == nil {
		return lockfile.ChainEvidence{}
	}
	predJSON, err := json.Marshal(res.Statement.Predicate.AsMap())
	if err != nil {
		return lockfile.ChainEvidence{}
	}
	filled := fillChainFromPredicate(predJSON)
	filled.Source = normalizeSource(filled.Source)
	filled.Workflow = normalizeWorkflow(filled.Workflow, filled.Builder)
	filled.State = lockfile.EvidenceVerified
	return filled
}
