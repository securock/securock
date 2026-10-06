package core_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
)

func TestNormalizeDigest(t *testing.T) {
	got := core.NormalizeDigest("sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
	want := "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	h1 := core.NormalizeDigest("h1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
	if h1 != "goh1:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" {
		t.Fatalf("h1 digest = %q", h1)
	}
}

func TestMatchDigest(t *testing.T) {
	data := []byte("test")
	normalized := core.NormalizeDigest("sha256-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
	if err := core.MatchDigest(normalized, data); err != nil {
		t.Fatalf("MatchDigest: %v", err)
	}
	if err := core.MatchDigest(normalized, []byte("other")); err == nil {
		t.Fatal("expected mismatch")
	}
	if err := core.MatchDigest("", data); err == nil {
		t.Fatal("expected missing digest error")
	}
}

func TestStrongDigest(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	if err := core.StrongDigest("sha256:" + sum); err != nil {
		t.Fatalf("sha256: %v", err)
	}
	sri := "sha256-" + base64.StdEncoding.EncodeToString(mustHex(t, sum))
	if err := core.StrongDigest(sri); err != nil {
		t.Fatalf("sha256 SRI: %v", err)
	}
	if err := core.StrongDigest("sha1:" + strings.Repeat("ab", 20)); err == nil {
		t.Fatal("sha1 must be rejected")
	}
	if err := core.StrongDigest("sha256:deadbeef"); err == nil {
		t.Fatal("short sha256 must be rejected")
	}
	if err := core.StrongDigest("not-a-digest"); err == nil {
		t.Fatal("opaque digest must be rejected")
	}
	if err := core.StrongDigest(""); err == nil {
		t.Fatal("empty digest must be rejected")
	}
	goh1 := "goh1:" + base64.StdEncoding.EncodeToString(mustHex(t, sum))
	if err := core.StrongDigest(goh1); err != nil {
		t.Fatalf("goh1: %v", err)
	}
}

func TestDigestFormatOK(t *testing.T) {
	if err := core.DigestFormatOK(""); err != nil {
		t.Fatal(err)
	}
	if err := core.DigestFormatOK("sha256:" + strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if err := core.DigestFormatOK("sha256:abcd"); err == nil {
		t.Fatal("short colon digest must fail")
	}
	// Unnormalized / opaque values remain readable in lockfiles.
	if err := core.DigestFormatOK("sha512-not-valid-base64!!"); err != nil {
		t.Fatalf("opaque SRI should be tolerated: %v", err)
	}
}

func mustHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	raw := make([]byte, len(hexStr)/2)
	for i := 0; i < len(raw); i++ {
		var b byte
		for _, c := range []byte{hexStr[i*2], hexStr[i*2+1]} {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			default:
				t.Fatalf("bad hex %q", hexStr)
			}
		}
		raw[i] = b
	}
	return raw
}
