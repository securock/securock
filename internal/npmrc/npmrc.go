package npmrc

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/network"
)

const DefaultRegistry = "https://registry.npmjs.org"

func Registry(project, name, tarball string) string {
	if tarball != "" {
		if strings.HasPrefix(tarball, "https://") || strings.HasPrefix(tarball, "http://") {
			return network.Origin(tarball)
		}
		return ""
	}
	if r := fromFile(filepath.Join(project, ".npmrc"), name); r != "" {
		return strings.TrimRight(r, "/")
	}
	return DefaultRegistry
}

func fromFile(path, name string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	general := ""
	scoped := ""
	scope := scopeOf(name)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch {
		case key == "registry":
			general = value
		case scope != "" && strings.EqualFold(key, scope+":registry"):
			scoped = value
		}
	}
	if scoped != "" {
		return scoped
	}
	return general
}

func scopeOf(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	scope, _, ok := strings.Cut(name, "/")
	if !ok {
		return ""
	}
	return scope
}
