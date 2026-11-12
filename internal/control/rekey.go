package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"fmt"
)

// Rekey atomically rewrites authenticated state using a new encryption key.
// Existing audit signatures and independent checkpoints remain valid. Historical
// backups keep their original keys; this operation does not rewrite them.
func (s *Store) Rekey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("state encryption requires a 32-byte key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.signer) != ed25519.PrivateKeySize {
		return fmt.Errorf("audit signer required for key rotation")
	}
	public := s.signer.Public().(ed25519.PublicKey)
	for _, t := range s.state.Tenants {
		if e := verifyState(t, public); e != nil {
			return e
		}
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	next, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	previous := s.aead
	s.aead = next
	if e = s.save(s.state); e != nil {
		s.aead = previous
		return e
	}
	return nil
}
