package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
)

type DSSE struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID     string `json:"keyid"`
		Signature string `json:"sig"`
	} `json:"signatures"`
}

type PinnedStatement struct {
	Identity, Digest string
	Record           Record
}

// ReadPinned authenticates caller-supplied SLSA statements with an independent
// Ed25519 pin. A signed claim is not an independent guarantee about the builder.
func ReadPinned(r io.Reader, key ed25519.PublicKey) ([]PinnedStatement, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid pinned package signer")
	}
	raw, e := io.ReadAll(io.LimitReader(r, 8<<20+1))
	if e != nil || len(raw) > 8<<20 {
		return nil, fmt.Errorf("package attestations exceed limit")
	}
	var manifest struct {
		Version      int    `json:"version"`
		Attestations []DSSE `json:"attestations"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Version != 1 || len(manifest.Attestations) == 0 || len(manifest.Attestations) > 1000 {
		return nil, fmt.Errorf("invalid package attestation manifest")
	}
	out := []PinnedStatement{}
	seen := map[string]bool{}
	for _, env := range manifest.Attestations {
		if env.PayloadType != "application/vnd.in-toto+json" || len(env.Signatures) == 0 || len(env.Signatures) > 20 {
			return nil, fmt.Errorf("unsupported package DSSE envelope")
		}
		payload, e := base64.StdEncoding.DecodeString(env.Payload)
		if e != nil {
			return nil, fmt.Errorf("invalid attestation payload")
		}
		pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(env.PayloadType), env.PayloadType, len(payload), payload))
		verified := false
		for _, signature := range env.Signatures {
			sig, e := base64.StdEncoding.DecodeString(signature.Signature)
			if e == nil && ed25519.Verify(key, pae, sig) {
				verified = true
				break
			}
		}
		if !verified {
			return nil, fmt.Errorf("package attestation signature verification failed")
		}
		var statement struct {
			Type     string `json:"_type"`
			Subjects []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
			PredicateType string          `json:"predicateType"`
			Predicate     json.RawMessage `json:"predicate"`
		}
		if json.Unmarshal(payload, &statement) != nil || statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != "https://slsa.dev/provenance/v1" || len(statement.Subjects) != 1 || len(statement.Subjects[0].Digest) != 1 || len(statement.Predicate) == 0 || bytes.Equal(bytes.TrimSpace(statement.Predicate), []byte("null")) {
			return nil, fmt.Errorf("expected a single-subject SLSA package statement")
		}
		subject := statement.Subjects[0]
		if subject.Name == "" || seen[subject.Name] {
			return nil, fmt.Errorf("duplicate or missing attestation identity")
		}
		seen[subject.Name] = true
		digest := ""
		for algorithm, value := range subject.Digest {
			digest = algorithm + ":" + value
		}
		if core.StrongDigest(digest) != nil {
			return nil, fmt.Errorf("attestation requires a strong package digest")
		}
		var predicate struct {
			BuildDefinition *struct {
				BuildType          string                     `json:"buildType"`
				ExternalParameters map[string]json.RawMessage `json:"externalParameters"`
			} `json:"buildDefinition"`
		}
		if json.Unmarshal(statement.Predicate, &predicate) != nil || predicate.BuildDefinition == nil || predicate.BuildDefinition.ExternalParameters == nil {
			return nil, fmt.Errorf("SLSA v1 build definition is required")
		}
		buildType, parseErr := url.Parse(predicate.BuildDefinition.BuildType)
		if parseErr != nil || buildType.Scheme == "" {
			return nil, fmt.Errorf("SLSA build type must be an absolute URI")
		}
		chain := fillChainFromPredicate(statement.Predicate)
		if chain.Builder == "" {
			return nil, fmt.Errorf("SLSA package statement requires a builder identity")
		}
		chain.State = lockfile.EvidenceVerified
		chain.PredicateType = statement.PredicateType
		out = append(out, PinnedStatement{Identity: subject.Name, Digest: core.NormalizeDigest(digest), Record: Record{Provenance: lockfile.EvidenceVerified, Signature: lockfile.EvidenceVerified, Chain: chain}})
	}
	return out, nil
}

// MatchPinned binds authenticated claims to exact dependency identities and
// lockfile digests. A mismatched claim is an operational failure, never safety.
func MatchPinned(statements []PinnedStatement, deps []ecosystem.Dependency) (map[string]Record, error) {
	claims := map[string]PinnedStatement{}
	for _, s := range statements {
		claims[s.Identity] = s
	}
	out := map[string]Record{}
	for _, dep := range deps {
		claim, ok := claims[Key(dep)]
		if !ok {
			continue
		}
		if core.StrongDigest(dep.Digest) != nil || core.NormalizeDigest(dep.Digest) != claim.Digest {
			return nil, fmt.Errorf("signed package identity has a different or unavailable dependency digest")
		}
		out[Key(dep)] = claim.Record
	}
	return out, nil
}

func LoadPinned(file, keyFile string, deps []ecosystem.Dependency) (map[string]Record, string, error) {
	if file == "" && keyFile == "" {
		return nil, "", nil
	}
	if file == "" || keyFile == "" {
		return nil, "", fmt.Errorf("package attestations and signer key must be supplied together")
	}
	k, e := os.Open(keyFile)
	if e != nil {
		return nil, "", fmt.Errorf("cannot read package signer key")
	}
	raw, e := io.ReadAll(io.LimitReader(k, 4097))
	k.Close()
	if e != nil || len(raw) > 4096 {
		return nil, "", fmt.Errorf("invalid package signer key file")
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil || len(key) != 32 {
		return nil, "", fmt.Errorf("invalid package signer public key")
	}
	f, e := os.Open(file)
	if e != nil {
		return nil, "", fmt.Errorf("cannot read package attestations")
	}
	defer f.Close()
	statements, e := ReadPinned(f, ed25519.PublicKey(key))
	if e != nil {
		return nil, "", e
	}
	matched, err := MatchPinned(statements, deps)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(key)
	return matched, fmt.Sprintf("sha256:%x", sum), nil
}
