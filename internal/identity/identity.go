// Package identity verifies access tokens against operator-pinned OIDC keys.
package identity

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

type Key struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}
type Binding struct {
	Subject string   `json:"subject"`
	Tenant  string   `json:"tenant"`
	Roles   []string `json:"roles"`
}
type Config struct {
	Issuer   string    `json:"issuer"`
	Audience string    `json:"audience"`
	Keys     []Key     `json:"keys"`
	Bindings []Binding `json:"bindings"`
}
type Principal struct {
	Subject string   `json:"subject"`
	Tenant  string   `json:"tenant"`
	Roles   []string `json:"roles"`
}

func (p Principal) Can(action string) bool {
	for _, role := range p.Roles {
		if role == "admin" {
			return true
		}
		switch role {
		case "reader":
			if action == "read" {
				return true
			}
		case "developer":
			if slices.Contains([]string{"read", "write", "scan", "integration"}, action) {
				return true
			}
		case "reviewer":
			if action == "read" || action == "approve" {
				return true
			}
		case "runner":
			if action == "run" {
				return true
			}
		case "provisioner":
			if action == "provision" {
				return true
			}
		}
	}
	return false
}
func (c Config) Validate() error {
	if !strings.HasPrefix(c.Issuer, "https://") || c.Audience == "" || len(c.Keys) == 0 || len(c.Bindings) == 0 {
		return fmt.Errorf("OIDC issuer, audience, pinned JWKS and subject bindings required")
	}
	seen := map[string]bool{}
	for _, k := range c.Keys {
		if seen[k.Kid] {
			return fmt.Errorf("duplicate OIDC key")
		}
		seen[k.Kid] = true
		if _, e := publicKey(k); e != nil {
			return e
		}
	}
	seen = map[string]bool{}
	for _, b := range c.Bindings {
		if b.Subject == "" || !ValidID(b.Tenant) || seen[b.Subject] || len(b.Roles) == 0 {
			return fmt.Errorf("invalid or ambiguous identity binding")
		}
		seen[b.Subject] = true
		for _, r := range b.Roles {
			if !slices.Contains([]string{"admin", "reader", "developer", "reviewer", "runner", "provisioner"}, r) {
				return fmt.Errorf("unknown role")
			}
		}
	}
	return nil
}
func ValidID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func publicKey(k Key) (*rsa.PublicKey, error) {
	n, e := base64.RawURLEncoding.DecodeString(k.N)
	if e != nil {
		return nil, fmt.Errorf("invalid OIDC modulus")
	}
	ex, e := base64.RawURLEncoding.DecodeString(k.E)
	if e != nil || len(ex) > 4 {
		return nil, fmt.Errorf("invalid OIDC exponent")
	}
	v := 0
	for _, b := range ex {
		v = v<<8 | int(b)
	}
	mod := new(big.Int).SetBytes(n)
	if k.Kty != "RSA" || k.Kid == "" || mod.BitLen() < 2048 || v < 3 || v%2 == 0 || k.Alg != "" && k.Alg != "RS256" || k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("unsupported OIDC verification key")
	}
	return &rsa.PublicKey{N: mod, E: v}, nil
}

// Verify accepts only RS256 access tokens for this API. It never follows jku/x5u URLs.
func (c Config) Verify(token string, now time.Time) (Principal, error) {
	denied := func() (Principal, error) { return Principal{}, fmt.Errorf("access token rejected") }
	if len(token) > 16384 {
		return denied()
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return denied()
	}
	var h struct {
		Alg  string   `json:"alg"`
		Kid  string   `json:"kid"`
		Crit []string `json:"crit"`
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || json.Unmarshal(raw, &h) != nil || h.Alg != "RS256" || len(h.Crit) != 0 {
		return denied()
	}
	var key *rsa.PublicKey
	for _, k := range c.Keys {
		if k.Kid == h.Kid {
			key, e = publicKey(k)
			if e != nil {
				return denied()
			}
		}
	}
	if key == nil {
		return denied()
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if e != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return denied()
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Exp      int64           `json:"exp"`
		Nbf      int64           `json:"nbf"`
		Issued   int64           `json:"iat"`
	}
	raw, e = base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || json.Unmarshal(raw, &claims) != nil || claims.Issuer != c.Issuer || claims.Subject == "" || claims.Exp <= now.Unix() || claims.Nbf > now.Unix() || claims.Issued > now.Unix()+30 {
		return denied()
	}
	aud := []string{}
	var one string
	if json.Unmarshal(claims.Audience, &one) == nil {
		aud = []string{one}
	} else if json.Unmarshal(claims.Audience, &aud) != nil {
		return denied()
	}
	if !slices.Contains(aud, c.Audience) {
		return denied()
	}
	for _, b := range c.Bindings {
		if b.Subject == claims.Subject {
			return Principal{b.Subject, b.Tenant, slices.Clone(b.Roles)}, nil
		}
	}
	return denied()
}
