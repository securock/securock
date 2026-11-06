package pipenv

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "Pipfile.lock"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pipenv" }

func (Ecosystem) OSVEcosystem() string { return "PyPI" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock pipfileLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	sources := map[string]string{}
	var order []string
	for _, src := range lock.Meta.Sources {
		sources[src.Name] = src.URL
		order = append(order, src.Name)
	}

	// default is installed everywhere, develop only with --dev; a package in both is runtime.
	merged := map[string]core.Dependency{}
	for _, section := range []struct {
		entries map[string]pipfilePackage
		scope   string
	}{{lock.Default, core.ScopeRuntime}, {lock.Develop, core.ScopeDev}} {
		for name, pkg := range section.entries {
			dep, ok := convert(name, pkg, sources, order)
			if !ok {
				continue
			}
			dep.Scope = section.scope
			key := core.NormalizePythonName(name) + "@" + dep.Version
			if prev, ok := merged[key]; ok {
				prev.Scope = core.MergeScope(prev.Scope, dep.Scope)
				merged[key] = prev
				continue
			}
			merged[key] = dep
		}
	}

	deps := make([]core.Dependency, 0, len(merged))
	for _, dep := range merged {
		deps = append(deps, dep)
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, nil
}

func convert(name string, pkg pipfilePackage, sources map[string]string, order []string) (core.Dependency, bool) {
	dep := core.Dependency{
		Ecosystem:  "pypi",
		Resolver:   "pipenv",
		SourceKind: core.SourceRegistry,
		Name:       name,
	}
	version := ""
	if strings.HasPrefix(pkg.Version, "==") {
		version = strings.TrimSpace(strings.TrimPrefix(pkg.Version, "=="))
	}

	switch {
	case pkg.Git != "":
		dep.SourceKind = core.SourceGit
		dep.Artifact = core.RemoteLocation(pkg.Git)
		dep.Resolved = pkg.Ref
		dep.Version = firstNonEmpty(version, pkg.Ref)
	case pkg.Path != "":
		dep.SourceKind = core.SourceFile
		dep.Version = firstNonEmpty(version, "path")
	case pkg.File != "":
		dep.SourceKind = core.SourceURL
		dep.Artifact = core.RemoteLocation(pkg.File)
		dep.Version = firstNonEmpty(version, "file")
	default:
		if version == "" {
			// Not an exact pin, so there is no artifact to record.
			return core.Dependency{}, false
		}
		dep.Version = version
		dep.Registry = registryFor(pkg.Index, sources, order)
		// hashes carries no file names, so several of them cannot be tied to one artifact.
		// Leave the digest unknown rather than pick one.
		if len(pkg.Hashes) == 1 {
			dep.Digest = core.NormalizeDigest(pkg.Hashes[0])
		}
	}
	if dep.Version == "" {
		return core.Dependency{}, false
	}
	return dep, true
}

// registryFor resolves an entry's index name to the origin of its source. A missing index
// is only resolved when the lockfile leaves no doubt which source is meant.
func registryFor(index string, sources map[string]string, order []string) string {
	if index == "" {
		if len(order) == 1 {
			index = order[0]
		}
	}
	raw := sources[index]
	if raw == "" {
		return ""
	}
	if origin := network.Origin(raw); origin != "" {
		return origin
	}
	return strings.TrimRight(raw, "/")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

type pipfileLock struct {
	Meta struct {
		Sources []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"sources"`
	} `json:"_meta"`
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
	Index   string   `json:"index"`
	Git     string   `json:"git"`
	Ref     string   `json:"ref"`
	Path    string   `json:"path"`
	File    string   `json:"file"`
}
