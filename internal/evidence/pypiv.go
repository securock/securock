package evidence

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	in_toto "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
)

// pep740Attestation is the PEP 740 attestation object. encoding/json
// decodes the base64 certificate / statement / signature fields into []byte.
type pep740Attestation struct {
	Version              int `json:"version"`
	VerificationMaterial struct {
		Certificate         []byte            `json:"certificate"`
		TransparencyEntries []json.RawMessage `json:"transparency_entries"`
	} `json:"verification_material"`
	Envelope struct {
		Statement []byte `json:"statement"`
		Signature []byte `json:"signature"`
	} `json:"envelope"`
}

// verifyPyPIAttestation reconstructs a Sigstore bundle from a PEP 740
// attestation and verifies it against the public-good trust root, the
// artifact digest, Trusted Publisher certificate identities, and the
// distribution filename bound in the in-toto subject.
func verifyPyPIAttestation(attJSON json.RawMessage, digest, filename string) (*verify.VerificationResult, bool) {
	if len(attJSON) == 0 || digest == "" || filename == "" {
		return nil, false
	}
	digest = core.NormalizeDigest(digest)
	alg, hexDigest, ok := strings.Cut(digest, ":")
	if !ok || hexDigest == "" {
		return nil, false
	}
	rawDigest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, false
	}

	var att pep740Attestation
	if err := json.Unmarshal(attJSON, &att); err != nil {
		return nil, false
	}
	if att.Version != 1 {
		return nil, false
	}
	if len(att.VerificationMaterial.Certificate) == 0 ||
		len(att.Envelope.Statement) == 0 ||
		len(att.Envelope.Signature) == 0 {
		return nil, false
	}

	b, err := pep740ToBundle(att)
	if err != nil || b == nil {
		return nil, false
	}

	verifier, err := sigstorePublicVerifier()
	if err != nil || verifier == nil {
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
	res, err := verifier.Verify(b, verify.NewPolicy(
		verify.WithArtifactDigest(strings.ToLower(alg), rawDigest),
		opts...,
	))
	if err != nil || res == nil || res.Statement == nil {
		return nil, false
	}
	if !isPyPIAttestation(res.Statement.GetPredicateType()) {
		return nil, false
	}
	if !pypiSubjectMatches(res.Statement.GetSubject(), filename, digest) {
		return nil, false
	}
	return res, true
}

func pep740ToBundle(a pep740Attestation) (*bundle.Bundle, error) {
	entries := make([]*protorekor.TransparencyLogEntry, 0, len(a.VerificationMaterial.TransparencyEntries))
	for _, raw := range a.VerificationMaterial.TransparencyEntries {
		var e protorekor.TransparencyLogEntry
		if err := protojson.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	pb := &protobundle.Bundle{
		// v0.3 is the first media type that carries a bare signing certificate.
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: a.VerificationMaterial.Certificate},
			},
			TlogEntries: entries,
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     a.Envelope.Statement,
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []*protodsse.Signature{{Sig: a.Envelope.Signature}},
			},
		},
	}
	return bundle.NewBundle(pb)
}

func isPyPIAttestation(predicateType string) bool {
	switch strings.TrimSpace(predicateType) {
	case "https://slsa.dev/provenance/v1",
		"https://docs.pypi.org/attestations/publish/v1":
		return true
	default:
		return false
	}
}

func pypiSubjectMatches(subjects []*in_toto.ResourceDescriptor, filename, digest string) bool {
	filename = strings.TrimSpace(filename)
	if filename == "" || len(subjects) != 1 {
		return false
	}
	sub := subjects[0]
	if sub == nil || strings.TrimSpace(sub.GetName()) != filename {
		return false
	}
	wantAlg, wantHex, ok := strings.Cut(digest, ":")
	if !ok {
		return false
	}
	wantAlg = strings.ToLower(wantAlg)
	for alg, hexDigest := range sub.GetDigest() {
		if strings.EqualFold(alg, wantAlg) && strings.EqualFold(hexDigest, wantHex) {
			return true
		}
	}
	return false
}

func chainFromPyPIVerified(res *verify.VerificationResult, base lockfile.ChainEvidence) lockfile.ChainEvidence {
	out := base
	if filled := chainFromVerifiedStatement(res); filled.State == lockfile.EvidenceVerified {
		if filled.Source != "" {
			out.Source = filled.Source
		}
		if filled.Commit != "" {
			out.Commit = filled.Commit
		}
		if filled.Ref != "" {
			out.Ref = filled.Ref
		}
		if filled.Builder != "" {
			out.Builder = filled.Builder
		}
		if filled.Workflow != "" {
			out.Workflow = filled.Workflow
		}
		if filled.PredicateType != "" {
			out.PredicateType = filled.PredicateType
		}
	} else if res != nil && res.Statement != nil {
		if pred := strings.TrimSpace(res.Statement.GetPredicateType()); pred != "" {
			out.PredicateType = pred
		}
	}
	if res != nil && res.Signature != nil && res.Signature.Certificate != nil {
		// Prefer the verified certificate identity over index-served
		// publisher claims when both are present.
		applyPublisherSAN(&out, res.Signature.Certificate.SubjectAlternativeName)
	}
	out.Source = normalizeSource(out.Source)
	out.Workflow = normalizeWorkflow(out.Workflow, out.Builder)
	out.State = lockfile.EvidenceVerified
	return out
}

// applyPublisherSAN overwrites chain identity fields from a verified
// Sigstore Trusted Publisher SAN such as
// https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0
func applyPublisherSAN(out *lockfile.ChainEvidence, san string) {
	san = strings.TrimSpace(san)
	if san == "" {
		return
	}
	out.Builder = san

	ref := ""
	identity := san
	if i := strings.LastIndex(san, "@"); i >= 0 {
		identity = san[:i]
		ref = san[i+1:]
	}
	if looksLikeRef(ref) {
		out.Ref = ref
	}

	const ghWorkflow = "/.github/workflows/"
	if i := strings.Index(identity, ghWorkflow); i >= 0 {
		repo := strings.TrimPrefix(identity[:i], "https://")
		repo = strings.TrimPrefix(repo, "http://")
		if looksLikeSource(repo) {
			out.Source = repo
		}
		wf := identity[i+len(ghWorkflow):]
		if looksLikeWorkflow(wf) {
			out.Workflow = wf
		}
		return
	}
	if strings.Contains(identity, "gitlab.com/") && looksLikeSource(identity) {
		out.Source = identity
	}
}

// fillChainFromPublisherSAN fills empty chain fields from a SAN (test helper path).
func fillChainFromPublisherSAN(out *lockfile.ChainEvidence, san string) {
	applyPublisherSAN(out, san)
}

// PyPIAttestationMetaForTest exposes pypiAttestationMeta for unit tests.
func PyPIAttestationMetaForTest(att json.RawMessage, digest, filename string) (string, bool) {
	return pypiAttestationMeta(att, digest, filename)
}

// FillChainFromPublisherSANForTest exposes SAN chain extraction for unit tests.
func FillChainFromPublisherSANForTest(san string) lockfile.ChainEvidence {
	out := lockfile.ChainEvidence{}
	applyPublisherSAN(&out, san)
	out.Source = normalizeSource(out.Source)
	out.Workflow = normalizeWorkflow(out.Workflow, out.Builder)
	return out
}
