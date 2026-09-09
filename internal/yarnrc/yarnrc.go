package yarnrc

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/network"
	"gopkg.in/yaml.v3"
)

const DefaultRegistry = "https://registry.yarnpkg.com"

func Registry(project, name, tarball string) string {
	tarball = strings.TrimSpace(tarball)
	if strings.HasPrefix(tarball, "https://") || strings.HasPrefix(tarball, "http://") {
		return network.Origin(tarball)
	}
	if tarball != "" {
		return ""
	}

	cfg := parsed{}
	var applied []os.FileInfo
	applyOnce := func(path string) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		for _, prev := range applied {
			if os.SameFile(prev, info) {
				return
			}
		}
		applied = append(applied, info)
		applyFile(&cfg, path, name)
	}

	if home, err := os.UserHomeDir(); err == nil {
		applyOnce(filepath.Join(home, ".yarnrc.yml"))
	}
	for _, dir := range dirsFromRoot(project) {
		applyOnce(filepath.Join(dir, ".yarnrc.yml"))
	}

	if cfg.scoped != "" {
		return strings.TrimRight(cfg.scoped, "/")
	}
	if cfg.general != "" {
		return strings.TrimRight(cfg.general, "/")
	}
	return DefaultRegistry
}

func dirsFromRoot(project string) []string {
	abs, err := filepath.Abs(project)
	if err != nil {
		abs = project
	}
	var fromLeaf []string
	dir := abs
	for i := 0; i < 64; i++ {
		fromLeaf = append(fromLeaf, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	out := make([]string, len(fromLeaf))
	for i := range fromLeaf {
		out[i] = fromLeaf[len(fromLeaf)-1-i]
	}
	return out
}

type parsed struct {
	general string
	scoped  string
}

type yarnFile struct {
	NpmRegistryServer string               `yaml:"npmRegistryServer"`
	NpmScopes         map[string]yarnScope `yaml:"npmScopes"`
}

type yarnScope struct {
	NpmRegistryServer string `yaml:"npmRegistryServer"`
}

func applyFile(cfg *parsed, path, name string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var file yarnFile
	if yaml.Unmarshal(raw, &file) != nil {
		return
	}
	if file.NpmRegistryServer != "" {
		cfg.general = file.NpmRegistryServer
	}
	scope := scopeOf(name)
	if scope == "" {
		return
	}
	if sc, ok := file.NpmScopes[scope]; ok && sc.NpmRegistryServer != "" {
		cfg.scoped = sc.NpmRegistryServer
		return
	}
	if sc, ok := file.NpmScopes["@"+scope]; ok && sc.NpmRegistryServer != "" {
		cfg.scoped = sc.NpmRegistryServer
	}
}

func scopeOf(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	scope, _, ok := strings.Cut(name, "/")
	if !ok {
		return ""
	}
	return strings.TrimPrefix(scope, "@")
}
