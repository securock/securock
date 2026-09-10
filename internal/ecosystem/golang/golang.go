package golang

import (
	"fmt"
	"os"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
	"golang.org/x/mod/modfile"
)

const (
	sumName = "go.sum"
	modName = "go.mod"
	goProxy = "https://proxy.golang.org"
)

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "go" }

func (Ecosystem) OSVEcosystem() string { return "Go" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, sumName)) ||
		core.FileExists(core.Join(path, modName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, modName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("missing go.mod")
		}
		return nil, err
	}
	mod, err := modfile.Parse(modName, raw, nil)
	if err != nil {
		return nil, err
	}

	sums := parseSum(core.Join(path, sumName))
	proxy := moduleProxy()
	excluded := map[string]struct{}{}
	for _, ex := range mod.Exclude {
		if ex == nil {
			continue
		}
		excluded[ex.Mod.Path+"@"+ex.Mod.Version] = struct{}{}
	}

	seen := map[string]struct{}{}
	var deps []core.Dependency
	for _, req := range mod.Require {
		if req == nil || req.Mod.Path == "" || req.Mod.Version == "" {
			continue
		}
		if _, skip := excluded[req.Mod.Path+"@"+req.Mod.Version]; skip {
			continue
		}
		dep := resolveRequire(req, mod.Replace, sums, proxy)
		key := core.Identity(dep)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deps = append(deps, dep)
	}
	return deps, nil
}

func resolveRequire(req *modfile.Require, replaces []*modfile.Replace, sums map[string]string, proxy string) core.Dependency {
	dep := core.Dependency{
		Ecosystem:  "go",
		Resolver:   "go",
		SourceKind: core.SourceRegistry,
		Name:       req.Mod.Path,
		Version:    req.Mod.Version,
		Digest:     sums[req.Mod.Path+"@"+req.Mod.Version],
	}
	fetch := req.Mod.Path
	rep := replacement(replaces, req.Mod.Path, req.Mod.Version)
	if rep != nil {
		dep.Requested = req.Mod.Path + "@" + req.Mod.Version
		if modfile.IsDirectoryPath(rep.New.Path) {
			dep.SourceKind = core.SourceFile
			dep.Digest = ""
			return dep
		}
		dep.Artifact = rep.New.Path
		fetch = rep.New.Path
		if rep.New.Version != "" {
			dep.Version = rep.New.Version
			dep.Resolved = rep.New.Version
			dep.Digest = sums[rep.New.Path+"@"+rep.New.Version]
		}
	}
	if !network.GoPrivate(fetch) {
		dep.Registry = proxy
	}
	return dep
}

func moduleProxy() string {
	raw, ok := os.LookupEnv("GOPROXY")
	if !ok || strings.TrimSpace(raw) == "" {
		raw = goProxy
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "direct" || part == "off" {
			return ""
		}
		return network.RegistryURL(part)
	}
	return ""
}

func replacement(replaces []*modfile.Replace, path, version string) *modfile.Replace {
	var generic *modfile.Replace
	for _, r := range replaces {
		if r == nil || r.Old.Path != path {
			continue
		}
		if r.Old.Version == "" {
			generic = r
			continue
		}
		if r.Old.Version == version {
			return r
		}
	}
	return generic
}

func parseSum(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		hash := fields[len(fields)-1]
		version := fields[len(fields)-2]
		name := strings.Join(fields[:len(fields)-2], " ")
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		key := name + "@" + version
		if _, ok := out[key]; ok {
			continue
		}
		out[key] = core.NormalizeDigest(hash)
	}
	return out
}
