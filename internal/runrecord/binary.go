package runrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

var binaryOnce sync.Once
var binaryID string
var binaryError error

// ExecutableIdentity identifies development builds without relying on an unknown version label.
func ExecutableIdentity() (string, error) {
	binaryOnce.Do(func() {
		path, e := os.Executable()
		if e != nil {
			binaryError = e
			return
		}
		f, e := os.Open(path)
		if e != nil {
			binaryError = e
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, e := io.Copy(h, f); e != nil {
			binaryError = e
			return
		}
		binaryID = "sha256:" + hex.EncodeToString(h.Sum(nil))
	})
	return binaryID, binaryError
}
