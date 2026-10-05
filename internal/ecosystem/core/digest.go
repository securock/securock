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
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return alg + "-" + payload
	}
	return alg + ":" + hex.EncodeToString(raw)
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
