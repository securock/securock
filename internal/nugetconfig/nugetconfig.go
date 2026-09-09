package nugetconfig

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

func Sources(project string) []string {
	var sources []string
	for _, path := range userConfigs() {
		sources = apply(sources, path)
	}
	for _, name := range []string{"nuget.config", "NuGet.Config"} {
		path := filepath.Join(project, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return apply(sources, path)
	}
	return sources
}

func userConfigs() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".nuget", "NuGet", "NuGet.Config"),
		filepath.Join(home, ".config", "NuGet", "NuGet.Config"),
	}
}

func apply(sources []string, path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return sources
	}
	var cfg nugetFile
	if xml.Unmarshal(raw, &cfg) != nil {
		return sources
	}
	if cfg.PackageSources.Clear != nil {
		sources = nil
	}
	for _, add := range cfg.PackageSources.Add {
		value := strings.TrimSpace(add.Value)
		if value == "" {
			continue
		}
		sources = append(sources, value)
	}
	return sources
}

type nugetFile struct {
	PackageSources struct {
		Clear *struct{} `xml:"clear"`
		Add   []struct {
			Value string `xml:"value,attr"`
		} `xml:"add"`
	} `xml:"packageSources"`
}
