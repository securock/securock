package control

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var tenantBucket = []byte("securock-tenants-v1")

type tenantRecord struct {
	ID     string  `json:"id"`
	Tenant *Tenant `json:"tenant"`
}

func tenantKey(id string) []byte {
	sum := sha256.Sum256([]byte(id))
	return []byte(hex.EncodeToString(sum[:]))
}

func (s *Store) openDatabase(create bool) error {
	db, e := bolt.Open(filepath.Join(s.dir, "state.db"), 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return e
	}
	s.db = db
	if create {
		return db.Update(func(tx *bolt.Tx) error { _, e := tx.CreateBucketIfNotExists(tenantBucket); return e })
	}

	return db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(tenantBucket)
		if bucket == nil {
			return fmt.Errorf("database tenant bucket missing")
		}
		encrypted := bucket.Get([]byte("manifest"))
		if len(encrypted) < s.aead.NonceSize() {
			return fmt.Errorf("database manifest missing")
		}
		expected, e := s.aead.Open(nil, encrypted[:s.aead.NonceSize()], encrypted[s.aead.NonceSize():], []byte("securock-control-manifest-v1"))
		if e != nil {
			return fmt.Errorf("database manifest authentication failed")
		}
		keys := []string{}
		if e = bucket.ForEach(func(key, raw []byte) error {
			if string(key) != "manifest" {
				keys = append(keys, string(key))
			}
			return nil
		}); e != nil {
			return e
		}
		sort.Strings(keys)
		actual, _ := json.Marshal(keys)
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("database tenant roster does not match authenticated manifest")
		}
		return bucket.ForEach(func(key, raw []byte) error {
			if string(key) == "manifest" {
				return nil
			}
			if len(raw) < s.aead.NonceSize() {
				return fmt.Errorf("invalid encrypted tenant record")
			}
			plain, e := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], key)
			if e != nil {
				return fmt.Errorf("tenant authentication failed")
			}
			var record tenantRecord
			if json.Unmarshal(plain, &record) != nil || record.ID == "" || record.Tenant == nil || string(tenantKey(record.ID)) != string(key) {
				return fmt.Errorf("invalid tenant record")
			}
			s.state.Tenants[record.ID] = record.Tenant
			return nil
		})
	})
}
func (s *Store) putTenant(tx *bolt.Tx, id string, t *Tenant) error {
	plain, e := json.Marshal(tenantRecord{id, t})
	if e != nil {
		return e
	}
	if len(plain) > 64<<20 {
		return fmt.Errorf("tenant state capacity exceeded")
	}
	key := tenantKey(id)
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw := s.aead.Seal(nonce, nonce, plain, key)
	return tx.Bucket(tenantBucket).Put(key, raw)
}
func (s *Store) saveDatabase(v State) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(tenantBucket)
		keep := map[string]bool{}
		for id, t := range v.Tenants {
			key := tenantKey(id)
			keep[string(key)] = true
			if e := s.putTenant(tx, id, t); e != nil {
				return e
			}
		}
		remove := [][]byte{}
		if e := bucket.ForEach(func(k, v []byte) error {
			if string(k) != "manifest" && !keep[string(k)] {
				remove = append(remove, append([]byte(nil), k...))
			}
			return nil
		}); e != nil {
			return e
		}
		for _, key := range remove {
			if e := bucket.Delete(key); e != nil {
				return e
			}
		}
		keys := make([]string, 0, len(keep))
		for key := range keep {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		plain, _ := json.Marshal(keys)
		nonce := make([]byte, s.aead.NonceSize())
		if _, e := rand.Read(nonce); e != nil {
			return e
		}
		encrypted := s.aead.Seal(nonce, nonce, plain, []byte("securock-control-manifest-v1"))
		return bucket.Put([]byte("manifest"), encrypted)
	})
}

// MigrateDatabase creates an independent database directory. Source state and
// audit history are authenticated before anything can be copied.
func MigrateDatabase(source, dest string, key, seed []byte) error {
	if _, e := os.Lstat(dest); !os.IsNotExist(e) {
		return fmt.Errorf("database migration requires an absent destination")
	}
	s, e := Open(source, key, nil)
	if e != nil {
		return e
	}
	defer s.Close()
	if e = s.SetSigner(seed); e != nil {
		return e
	}
	if e = os.Mkdir(dest, 0700); e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(dest)
		}
	}()
	target := &Store{dir: dest, aead: s.aead, state: s.Read()}
	if e = target.openDatabase(true); e != nil {
		if target.db != nil {
			target.db.Close()
		}
		return e
	}
	if e = target.saveDatabase(target.state); e != nil {
		target.db.Close()
		return e
	}
	if e = target.db.Close(); e != nil {
		return e
	}
	success = true
	return nil
}

// Tenant returns a private copy of one tenant, avoiding copies of unrelated
// customer reports on every authenticated request.
func (s *Store) Tenant(id string) *Tenant {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, _ := json.Marshal(s.state.Tenants[id])
	var t *Tenant
	_ = json.Unmarshal(raw, &t)
	return t
}
func (s *Store) updateTenant(id string, fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state.Tenants[id]
	if old == nil {
		return fmt.Errorf("tenant not found")
	}
	raw, e := json.Marshal(old)
	if e != nil {
		return e
	}
	var tenant Tenant
	if e = json.Unmarshal(raw, &tenant); e != nil {
		return e
	}
	isolated := State{Version: 1, Tenants: map[string]*Tenant{id: &tenant}}
	if e = fn(&isolated); e != nil {
		return e
	}
	if len(isolated.Tenants) != 1 || isolated.Tenants[id] == nil {
		return fmt.Errorf("tenant update cannot change tenant boundaries")
	}
	if e := validateState(isolated); e != nil {
		return e
	}
	for tenantID, other := range s.state.Tenants {
		if tenantID == id {
			continue
		}
		for subject := range isolated.Tenants[id].Members {
			if _, exists := other.Members[subject]; exists {
				return fmt.Errorf("subject already bound")
			}
		}
	}
	next := State{Version: 1, Tenants: make(map[string]*Tenant, len(s.state.Tenants))}
	for key, t := range s.state.Tenants {
		next.Tenants[key] = t
	}
	next.Tenants[id] = isolated.Tenants[id]
	if s.db != nil {
		e = s.db.Update(func(tx *bolt.Tx) error { return s.putTenant(tx, id, next.Tenants[id]) })
	} else {
		e = s.save(next)
	}
	if e != nil {
		return e
	}
	s.state = next
	return nil
}

func (s *Store) backupDatabase(path string) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			os.Remove(path)
		}
	}()
	e = s.db.View(func(tx *bolt.Tx) error { _, e := tx.WriteTo(f); return e })
	if e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	success = true
	return nil
}

func RestoreDatabase(path, dir string, key, seed []byte) error {
	if _, e := os.Lstat(dir); !os.IsNotExist(e) {
		return fmt.Errorf("restore requires an absent destination directory")
	}
	input, e := os.Open(path)
	if e != nil {
		return e
	}
	defer input.Close()
	if e = os.Mkdir(dir, 0700); e != nil {
		return e
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(dir)
		}
	}()
	output, e := os.OpenFile(filepath.Join(dir, "state.db"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(output, io.LimitReader(input, 1<<30+1))
	if e == nil && n > 1<<30 {
		e = fmt.Errorf("database backup exceeds 1 GiB restore limit")
	}
	if e == nil {
		e = output.Sync()
	}
	closeErr := output.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	s, e := Open(dir, key, nil)
	if e != nil {
		return e
	}
	if e = s.SetSigner(seed); e != nil {
		s.Close()
		return e
	}
	if e = s.Close(); e != nil {
		return e
	}
	success = true
	return nil
}
