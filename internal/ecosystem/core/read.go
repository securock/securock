package core

import (
	"fmt"
	"io"
	"os"
)

// MaxLockfileBytes is the maximum size of a language lockfile Securock will
// load. Larger files fail closed rather than parsing unbounded input.
const MaxLockfileBytes = 64 << 20

// ReadFile reads path and fails if the file exceeds MaxLockfileBytes.
func ReadFile(path string) ([]byte, error) {
	return ReadFileLimit(path, MaxLockfileBytes)
}

// ReadFileLimit reads path and fails if the file exceeds max bytes.
func ReadFileLimit(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s exceeds %d byte limit", path, max)
	}
	return raw, nil
}
