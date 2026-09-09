package bun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/npmrc"
)

const (
	lockfileName = "bun.lock"
	legacyName   = "bun.lockb"
)

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "bun" }

func (Ecosystem) OSVEcosystem() string { return "npm" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName)) || core.FileExists(core.Join(path, legacyName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	if !core.FileExists(core.Join(path, lockfileName)) {
		return nil, fmt.Errorf("bun.lockb is unsupported; migrate to bun.lock first")
	}
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}
	raw = stripJSONC(raw)

	var lock bunLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var deps []core.Dependency
	for _, pkg := range lock.Packages {
		name, version, tarball, integrity := parsePackage(pkg)
		if name == "" || version == "" {
			continue
		}
		id := name + "@" + version
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		kind := classify(version, tarball)
		registry := ""
		if kind == core.SourceRegistry {
			registry = npmrc.Registry(path, name, tarball)
		}
		deps = append(deps, core.Dependency{
			Ecosystem:  "npm",
			Resolver:   "bun",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    version,
			Digest:     core.NormalizeDigest(integrity),
		})
	}
	return deps, nil
}

type bunLock struct {
	Packages map[string]json.RawMessage `json:"packages"`
}

func parsePackage(raw json.RawMessage) (name, version, tarball, integrity string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", "", "", ""
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", "", "", ""
		}
		name, version := splitLocator(s)
		return name, version, "", ""
	}
	var parts []json.RawMessage
	if json.Unmarshal(raw, &parts) != nil || len(parts) == 0 {
		return "", "", "", ""
	}
	var locator string
	if json.Unmarshal(parts[0], &locator) != nil {
		return "", "", "", ""
	}
	name, version = splitLocator(locator)
	for _, part := range parts[1:] {
		var s string
		if json.Unmarshal(part, &s) != nil {
			continue
		}
		switch {
		case strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"):
			tarball = s
		case strings.HasPrefix(s, "sha256-") || strings.HasPrefix(s, "sha512-") || strings.HasPrefix(s, "sha1-") || strings.HasPrefix(s, "sha256:") || strings.HasPrefix(s, "sha512:"):
			integrity = s
		}
	}
	return name, version, tarball, integrity
}

func splitLocator(locator string) (name, version string) {
	locator = strings.TrimSpace(locator)
	at := strings.LastIndex(locator, "@")
	if at <= 0 {
		return locator, ""
	}
	return locator[:at], locator[at+1:]
}

func classify(version, tarball string) string {
	switch {
	case strings.HasPrefix(version, "workspace:"):
		return core.SourceWorkspace
	case strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "link:"):
		return core.SourceFile
	case strings.HasPrefix(version, "git") || strings.HasPrefix(version, "github:") || strings.HasPrefix(version, "gitlab:"):
		return core.SourceGit
	case strings.HasPrefix(tarball, "https://") || strings.HasPrefix(tarball, "http://"):
		return core.SourceRegistry
	case strings.Contains(version, ":"):
		return core.SourceURL
	default:
		return core.SourceRegistry
	}
}

func stripJSONC(raw []byte) []byte {
	var out bytes.Buffer
	inString := false
	escape := false
	for i := 0; i < len(raw); {
		c := raw[i]
		if inString {
			out.WriteByte(c)
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				inString = false
			}
			i++
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(c)
			i++
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '/' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(raw) && raw[i+1] == '*' {
			i += 2
			for i < len(raw) && !(raw[i] == '*' && i+1 < len(raw) && raw[i+1] == '/') {
				i++
			}
			if i+1 < len(raw) {
				i += 2
			}
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(raw) && (raw[j] == ' ' || raw[j] == '\t' || raw[j] == '\n' || raw[j] == '\r') {
				j++
			}
			if j < len(raw) && (raw[j] == '}' || raw[j] == ']') {
				i++
				continue
			}
		}
		out.WriteByte(c)
		i++
	}
	return out.Bytes()
}
