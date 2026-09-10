package goenv

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
)

const defaultProxy = "https://proxy.golang.org,direct"

// Env is the effective Go module environment, matching the go command:
// a non-empty OS value overrides the user GOENV file (`go env -w`),
// which overrides Go's defaults.
type Env struct {
	GOPROXY   string
	GOPRIVATE string
	GONOPROXY string
}

func Load() Env {
	file := readUserFile()
	private := get("GOPRIVATE", file, "")
	return Env{
		GOPROXY:   get("GOPROXY", file, defaultProxy),
		GOPRIVATE: private,
		GONOPROXY: get("GONOPROXY", file, private),
	}
}

func (e Env) Private(path string) bool {
	return module.MatchPrefixPatterns(e.GOPRIVATE, path)
}

func (e Env) NoProxy(path string) bool {
	return module.MatchPrefixPatterns(e.GONOPROXY, path)
}

// Proxy returns the single determined module proxy URL, or empty when
// the GOPROXY list is direct/off or contains more than one distinct proxy.
// `direct` and `off` are not origins; they may follow a single URL.
func (e Env) Proxy() string {
	var found string
	for raw := e.GOPROXY; raw != ""; {
		var part string
		if i := strings.IndexAny(raw, ",|"); i >= 0 {
			part, raw = raw[:i], raw[i+1:]
		} else {
			part, raw = raw, ""
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "direct" || part == "off" {
			return found
		}
		u := canonicalProxy(part)
		if found != "" && found != u {
			return ""
		}
		found = u
	}
	return found
}

func get(key string, file map[string]string, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if v := file[key]; v != "" {
		return v
	}
	return def
}

func readUserFile() map[string]string {
	out := map[string]string{}
	name := envFile()
	if name == "" {
		return out
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return out
	}
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		i := bytes.IndexByte(line, '=')
		if i < 0 || line[0] < 'A' || 'Z' < line[0] {
			continue
		}
		out[string(line[:i])] = string(line[i+1:])
	}
	return out
}

func envFile() string {
	if file := os.Getenv("GOENV"); file != "" {
		if file == "off" {
			return ""
		}
		return file
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "go", "env")
}

func canonicalProxy(raw string) string {
	if strings.ContainsAny(raw, ".:/") && !strings.Contains(raw, ":/") && !filepath.IsAbs(raw) {
		raw = "https://" + raw
	}
	return strings.TrimRight(raw, "/")
}
