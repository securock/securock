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
	tarball = strings.TrimSpace(tarball)
	if strings.HasPrefix(tarball, "https://") || strings.HasPrefix(tarball, "http://") {
		return network.Origin(tarball)
	}
	if tarball != "" {
		return ""
	}

	cfg := parsed{}
	if home, err := os.UserHomeDir(); err == nil {
		applyFile(&cfg, filepath.Join(home, ".npmrc"), name)
	}
	applyFile(&cfg, filepath.Join(project, ".npmrc"), name)
	applyEnv(&cfg, name)
	if cfg.scoped != "" {
		return strings.TrimRight(cfg.scoped, "/")
	}
	return strings.TrimRight(cfg.general, "/")
}

type parsed struct {
	general string
	scoped  string
}

func applyFile(cfg *parsed, path, name string) {
	general, scoped := fromFile(path, name)
	if general != "" {
		cfg.general = general
	}
	if scoped != "" {
		cfg.scoped = scoped
	}
}

func applyEnv(cfg *parsed, name string) {
	if v := envValue("npm_config_registry", "NPM_CONFIG_REGISTRY"); v != "" {
		cfg.general = v
	}
	if scope := scopeOf(name); scope != "" {
		if v := envValue("npm_config_"+scope+":registry"); v != "" {
			cfg.scoped = v
		}
	}
}

func envValue(keys ...string) string {
	for _, key := range keys {
		if v := strings.Trim(strings.TrimSpace(os.Getenv(key)), `"'`); v != "" {
			return v
		}
	}
	return ""
}

func fromFile(path, name string) (general, scoped string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()

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
	return general, scoped
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
