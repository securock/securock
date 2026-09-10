package bundler

import (
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "Gemfile.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "bundler" }

func (Ecosystem) OSVEcosystem() string { return "RubyGems" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	checksums := parseChecksums(string(raw))
	seen := map[string]struct{}{}
	var deps []core.Dependency
	section := ""
	remote := ""
	revision := ""
	for line := range strings.SplitSeq(string(raw), "\n") {
		if header, ok := sectionHeader(line); ok {
			section = header
			remote = ""
			revision = ""
			continue
		}
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "remote:") && (section == "GEM" || section == "GIT" || section == "PATH") {
			remote = strings.TrimSpace(strings.TrimPrefix(trimmed, "remote:"))
			continue
		}
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "revision:") && (section == "GIT" || section == "PATH") {
			revision = strings.TrimSpace(strings.TrimPrefix(trimmed, "revision:"))
			continue
		}
		if section != "GEM" && section != "GIT" && section != "PATH" {
			continue
		}
		name, version, ok := gemSpec(line)
		if !ok {
			continue
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		kind, registry := classify(section, remote)
		dep := core.Dependency{
			Ecosystem:  "rubygems",
			Resolver:   "bundler",
			Registry:   registry,
			SourceKind: kind,
			Name:       name,
			Version:    version,
			Digest:     checksums[key],
		}
		if kind == core.SourceGit {
			dep.Artifact = core.RemoteLocation(remote)
			dep.Resolved = revision
		}
		deps = append(deps, dep)
	}
	return deps, nil
}

func sectionHeader(line string) (string, bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return "", false
	}
	line = strings.TrimSpace(line)
	switch line {
	case "GEM", "GIT", "PATH", "PLATFORMS", "DEPENDENCIES", "CHECKSUMS", "BUNDLED WITH", "RUBY VERSION":
		return line, true
	}
	if strings.ToUpper(line) == line && strings.IndexFunc(line, func(r rune) bool {
		return r != ' ' && r != '_' && (r < 'A' || r > 'Z')
	}) < 0 {
		return line, true
	}
	return "", false
}

func gemSpec(line string) (name, version string, ok bool) {
	indent := len(line) - len(strings.TrimLeft(line, " "))
	if indent != 4 {
		return "", "", false
	}
	line = strings.TrimSpace(line)
	open := strings.LastIndex(line, " (")
	if open <= 0 || !strings.HasSuffix(line, ")") {
		return "", "", false
	}
	name = strings.TrimSpace(line[:open])
	version = strings.TrimSuffix(line[open+2:], ")")
	if name == "" || version == "" || strings.ContainsAny(version, "<>!~=") {
		return "", "", false
	}
	return name, version, true
}

func classify(section, remote string) (kind, registry string) {
	switch section {
	case "GIT":
		return core.SourceGit, ""
	case "PATH":
		return core.SourceFile, ""
	default:
		return core.SourceRegistry, strings.TrimRight(remote, "/")
	}
}

func parseChecksums(raw string) map[string]string {
	out := map[string]string{}
	inChecksums := false
	for line := range strings.SplitSeq(raw, "\n") {
		if header, ok := sectionHeader(line); ok {
			inChecksums = header == "CHECKSUMS"
			continue
		}
		if !inChecksums {
			continue
		}
		line = strings.TrimSpace(line)
		spec, rest, found := strings.Cut(line, ") ")
		if !found {
			continue
		}
		name, version, ok := gemSpec("    " + spec + ")")
		if !ok {
			continue
		}
		for _, part := range strings.Split(rest, ",") {
			part = strings.TrimSpace(part)
			alg, payload, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			if strings.EqualFold(alg, "sha256") || strings.EqualFold(alg, "sha512") {
				out[name+"@"+version] = core.NormalizeDigest(alg + ":" + payload)
				break
			}
		}
	}
	return out
}
