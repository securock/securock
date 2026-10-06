package core

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func NormalizeDigest(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	switch {
	case strings.HasPrefix(raw, "h1:"):
		return "goh1:" + strings.TrimPrefix(raw, "h1:")
	case strings.HasPrefix(raw, "goh1:"):
		return raw
	case strings.HasPrefix(raw, "sha256:"):
		return raw
	case strings.HasPrefix(raw, "sha512:"):
		return raw
	case strings.HasPrefix(raw, "sha384:"):
		return raw
	case strings.HasPrefix(raw, "sha1:"):
		return raw
	}

	if alg, payload, ok := strings.Cut(raw, "-"); ok && isHashAlg(alg) {
		return fromBase64(alg, payload)
	}

	if len(raw) == 64 && isHex(raw) {
		return "sha256:" + strings.ToLower(raw)
	}

	return raw
}

func fromBase64(alg, payload string) string {
	raw, err := decodeBase64(payload)
	if err != nil {
		return alg + "-" + payload
	}
	want, ok := digestSize(alg)
	if !ok || len(raw) != want {
		return alg + "-" + payload
	}
	return strings.ToLower(alg) + ":" + hex.EncodeToString(raw)
}

func decodeBase64(payload string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(payload); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(payload, "=")); err == nil {
		return raw, nil
	}
	return nil, fmt.Errorf("invalid base64")
}

func digestSize(alg string) (int, bool) {
	switch strings.ToLower(alg) {
	case "sha1":
		return sha1.Size, true
	case "sha256":
		return sha256.Size, true
	case "sha384":
		return sha512.Size384, true
	case "sha512":
		return sha512.Size, true
	default:
		return 0, false
	}
}

// MatchDigest reports whether data hashes to the normalized digest
// (algorithm:hex). Unsupported algorithms return an error.
func MatchDigest(normalized string, data []byte) error {
	normalized = strings.TrimSpace(normalized)
	if normalized == "" {
		return fmt.Errorf("missing digest")
	}
	alg, payload, ok := strings.Cut(normalized, ":")
	if !ok || alg == "" || payload == "" {
		return fmt.Errorf("unrecognized digest %q", normalized)
	}
	sum, err := hashSum(alg, data)
	if err != nil {
		return err
	}
	got := hex.EncodeToString(sum)
	if !strings.EqualFold(got, payload) {
		return fmt.Errorf("digest mismatch: want %s, got %s:%s", normalized, strings.ToLower(alg), got)
	}
	return nil
}

// StrongDigest reports whether raw is a well-formed digest using a
// strong algorithm (sha256, sha384, sha512, or goh1). sha1 and opaque
// strings are rejected.
func StrongDigest(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("missing digest")
	}
	normalized := NormalizeDigest(raw)
	alg, payload, ok := strings.Cut(normalized, ":")
	if !ok || alg == "" || payload == "" {
		return fmt.Errorf("unrecognized digest %q", raw)
	}
	switch strings.ToLower(alg) {
	case "sha256":
		if !isHex(payload) || len(payload) != 64 {
			return fmt.Errorf("invalid sha256 digest %q", raw)
		}
	case "sha384":
		if !isHex(payload) || len(payload) != 96 {
			return fmt.Errorf("invalid sha384 digest %q", raw)
		}
	case "sha512":
		if !isHex(payload) || len(payload) != 128 {
			return fmt.Errorf("invalid sha512 digest %q", raw)
		}
	case "goh1":
		rawBytes, err := decodeBase64(payload)
		if err != nil || len(rawBytes) != sha256.Size {
			return fmt.Errorf("invalid goh1 digest %q", raw)
		}
	case "sha1":
		return fmt.Errorf("weak digest algorithm sha1")
	default:
		return fmt.Errorf("unsupported digest algorithm %q", alg)
	}
	return nil
}

// DigestFormatOK reports whether a non-empty digest uses a known
// algorithm:payload shape. Empty digests are allowed. Legacy SRI
// strings that fail to normalize are accepted so existing lockfiles
// remain readable; require_digest rejects those via StrongDigest.
func DigestFormatOK(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	normalized := NormalizeDigest(raw)
	alg, payload, ok := strings.Cut(normalized, ":")
	if !ok {
		// Opaque digests (for example unresolved SRI or git revisions)
		// are tolerated in lockfiles.
		return nil
	}
	switch strings.ToLower(alg) {
	case "sha1":
		if !isHex(payload) || len(payload) != 40 {
			return fmt.Errorf("invalid sha1 digest %q", raw)
		}
	case "sha256":
		if !isHex(payload) || len(payload) != 64 {
			return fmt.Errorf("invalid sha256 digest %q", raw)
		}
	case "sha384":
		if !isHex(payload) || len(payload) != 96 {
			return fmt.Errorf("invalid sha384 digest %q", raw)
		}
	case "sha512":
		if !isHex(payload) || len(payload) != 128 {
			return fmt.Errorf("invalid sha512 digest %q", raw)
		}
	case "goh1":
		rawBytes, err := decodeBase64(payload)
		if err != nil || len(rawBytes) != sha256.Size {
			return fmt.Errorf("invalid goh1 digest %q", raw)
		}
	default:
		return fmt.Errorf("unknown digest algorithm %q", alg)
	}
	return nil
}

func hashSum(alg string, data []byte) ([]byte, error) {
	switch strings.ToLower(alg) {
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:], nil
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:], nil
	case "sha384":
		sum := sha512.Sum384(data)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
}

func isHashAlg(alg string) bool {
	switch strings.ToLower(alg) {
	case "sha1", "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

func isHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
