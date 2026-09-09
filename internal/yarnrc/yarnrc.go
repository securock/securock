package yarnrc

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/network"
	"gopkg.in/yaml.v3"
)

func Registry(project, name, tarball string) string {
	tarball = strings.TrimSpace(tarball)
	if strings.HasPrefix(tarball, "https://") || strings.HasPrefix(tarball, "http://") {
		return network.Origin(tarball)
	}
	if tarball != "" {
		return ""
	}

	cfg := parsed{}
	if home, err := os.UserHomeDir(); err == nil {
		applyFile(&cfg, filepath.Join(home, ".yarnrc.yml"), name)
	}
	applyFile(&cfg, filepath.Join(project, ".yarnrc.yml"), name)
	if cfg.scoped != "" {
		return strings.TrimRight(cfg.scoped, "/")
	}
	return strings.TrimRight(cfg.general, "/")
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
