package core

import (
	"encoding/base64"
	"encoding/hex"
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
