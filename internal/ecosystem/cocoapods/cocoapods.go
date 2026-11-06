package cocoapods

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/securock/securock/internal/ecosystem/core"
)

const lockfileName = "Podfile.lock"

// trunkRegistry is the CDN behind the default "trunk" spec repo.
const trunkRegistry = "https://cdn.cocoapods.org"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "cocoapods" }

// OSV has no CocoaPods ecosystem; osv.QueryEcosystem skips these artifacts so they stay
// unknown rather than being reported clean.
func (Ecosystem) OSVEcosystem() string { return "" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := core.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock struct {
		Pods     []any               `yaml:"PODS"`
		Repos    map[string][]string `yaml:"SPEC REPOS"`
		External map[string]any      `yaml:"EXTERNAL SOURCES"`
		Checkout map[string]any      `yaml:"CHECKOUT OPTIONS"`
	}
	if err := yaml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	// Subspecs (Firebase/Core) are part of their root pod, which is what gets fetched.
	versions := map[string]string{}
	needs := map[string]map[string]struct{}{}
	for _, entry := range lock.Pods {
		switch e := entry.(type) {
		case string:
			addPod(versions, e)
		case map[string]any:
			for head, list := range e {
				name := addPod(versions, head)
				if name == "" {
					continue
				}
				children, _ := list.([]any)
				for _, c := range children {
					if s, ok := c.(string); ok {
						if dep := rootName(s); dep != "" && dep != name {
							if needs[name] == nil {
								needs[name] = map[string]struct{}{}
							}
							needs[name][dep] = struct{}{}
						}
					}
				}
			}
		}
	}

	trunk := map[string]bool{}
	for repo, pods := range lock.Repos {
		if !isTrunk(repo) {
			continue
		}
		for _, p := range pods {
			trunk[rootName(p)] = true
		}
	}

	names := make([]string, 0, len(versions))
	for name := range versions {
		names = append(names, name)
	}
	sort.Strings(names)

	deps := make([]core.Dependency, 0, len(names))
	for _, name := range names {
		dep := core.Dependency{
			Ecosystem:  "cocoapods",
			Resolver:   "cocoapods",
			SourceKind: core.SourceRegistry,
			Name:       name,
			Version:    versions[name],
		}
		if src, ok := lock.External[name].(map[string]any); ok {
			switch {
			case str(src[":git"]) != "":
				dep.SourceKind = core.SourceGit
				dep.Artifact = core.RemoteLocation(str(src[":git"]))
				if co, ok := lock.Checkout[name].(map[string]any); ok {
					dep.Resolved = str(co[":commit"])
				}
			case str(src[":path"]) != "":
				dep.SourceKind = core.SourceFile
			default:
				// Podspec, or a source this does not understand: not a registry pod.
				dep.SourceKind = core.SourceURL
			}
		} else if trunk[name] {
			dep.Registry = trunkRegistry
		}
		deps = append(deps, dep)
	}

	ids := map[string]string{}
	for _, dep := range deps {
		ids[dep.Name] = core.Identity(dep)
	}
	for i, dep := range deps {
		var edges []string
		for target := range needs[dep.Name] {
			if id, ok := ids[target]; ok {
				edges = append(edges, id)
			}
		}
		deps[i].DependsOn = core.UnionIdentities(nil, edges)
	}
	return deps, nil
}

// addPod records "Name (1.2.3)" and returns the root pod name, or "" if malformed.
func addPod(versions map[string]string, entry string) string {
	open := strings.LastIndex(entry, " (")
	if open < 0 || !strings.HasSuffix(entry, ")") {
		return ""
	}
	name := rootName(entry[:open])
	version := strings.TrimSpace(entry[open+2 : len(entry)-1])
	if name == "" || version == "" {
		return ""
	}
	if _, ok := versions[name]; !ok {
		versions[name] = version
	}
	return name
}

// rootName strips a version constraint and subspec from a dependency string.
func rootName(s string) string {
	if i := strings.Index(s, " ("); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func isTrunk(repo string) bool {
	repo = strings.TrimRight(repo, "/")
	return repo == "trunk" || repo == trunkRegistry
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}
