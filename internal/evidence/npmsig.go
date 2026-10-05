package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/pkg/lockfile"
)

type npmSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type registryKey struct {
	KeyID   string
	Expires time.Time
	HasExp  bool
	Pub     *ecdsa.PublicKey
}

type keyCache struct {
	mu    sync.Mutex
	byReg map[string]map[string]registryKey
}

func (c *NPM) verifySignature(ctx context.Context, registry, name, version, integrity, digest string, sigs []npmSignature) lockfile.EvidenceState {
	if len(sigs) == 0 {
		return lockfile.EvidenceMissing
	}
	if integrity == "" {
		return lockfile.EvidencePresent
	}

	keys, err := c.registryKeys(ctx, registry)
	if err != nil || len(keys) == 0 {
		return lockfile.EvidencePresent
	}

	msg := []byte(name + "@" + version + ":" + integrity)
	verified := false
	for _, sig := range sigs {
		key, ok := keys[sig.KeyID]
		if !ok || key.Pub == nil {
			continue
		}
		raw, err := decodeBase64(sig.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(key.Pub, sha256Sum(msg), raw) {
			verified = true
			break
		}
	}
	if !verified {
		return lockfile.EvidencePresent
	}
	if digest == "" || core.NormalizeDigest(integrity) != digest {
		// Cryptographically valid for the registry integrity, but not
		// bound to the locked artifact digest.
		return lockfile.EvidencePresent
	}
	return lockfile.EvidenceVerified
}

func (c *NPM) registryKeys(ctx context.Context, registry string) (map[string]registryKey, error) {
	registry = strings.TrimRight(registry, "/")
	c.keysOnce.Do(func() {
		c.keys = &keyCache{byReg: make(map[string]map[string]registryKey)}
	})
	c.keys.mu.Lock()
	if cached, ok := c.keys.byReg[registry]; ok {
		c.keys.mu.Unlock()
		return cached, nil
	}
	c.keys.mu.Unlock()

	endpoint := registry + "/-/npm/v1/keys"
	res, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry keys: status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	parsed, err := parseRegistryKeys(raw)
	if err != nil {
		return nil, err
	}

	c.keys.mu.Lock()
	c.keys.byReg[registry] = parsed
	c.keys.mu.Unlock()
	return parsed, nil
}

func parseRegistryKeys(raw []byte) (map[string]registryKey, error) {
	var doc struct {
		Keys []struct {
			Expires *string `json:"expires"`
			KeyID   string  `json:"keyid"`
			KeyType string  `json:"keytype"`
			Scheme  string  `json:"scheme"`
			Key     string  `json:"key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]registryKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.KeyType != "" && k.KeyType != "ecdsa-sha2-nistp256" {
			continue
		}
		if k.Scheme != "" && k.Scheme != "ecdsa-sha2-nistp256" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			continue
		}
		pubAny, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		pub, ok := pubAny.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		// Reject key material whose fingerprint does not match keyid.
		want := keyFingerprint(der)
		if k.KeyID == "" || k.KeyID != want {
			continue
		}
		rk := registryKey{KeyID: k.KeyID, Pub: pub}
		if k.Expires != nil && strings.TrimSpace(*k.Expires) != "" {
			if t, err := time.Parse(time.RFC3339Nano, *k.Expires); err == nil {
				rk.Expires = t
				rk.HasExp = true
			} else if t, err := time.Parse(time.RFC3339, *k.Expires); err == nil {
				rk.Expires = t
				rk.HasExp = true
			}
		}
		// Expired keys remain valid for verifying historical signatures;
		// the registry continues to publish them for that purpose.
		out[k.KeyID] = rk
	}
	return out, nil
}

func keyFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

func sha256Sum(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}
