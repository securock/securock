package cli

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func serviceSecret(env, file string) ([]byte, error) {
	text := os.Getenv(env)
	if file != "" {
		f, e := os.Open(file)
		if e != nil {
			return nil, fmt.Errorf("cannot open service secret file")
		}
		defer f.Close()
		raw, e := io.ReadAll(io.LimitReader(f, 4097))
		if e != nil || len(raw) > 4096 {
			return nil, fmt.Errorf("invalid service secret file")
		}
		text = strings.TrimSpace(string(raw))
	}
	raw, e := base64.StdEncoding.DecodeString(text)
	if e != nil || len(raw) != 32 {
		return nil, fmt.Errorf("service secret must be a base64 32-byte key")
	}
	return raw, nil
}
