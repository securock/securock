package pdm

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/network"
)

const lockfileName = "pdm.lock"

const defaultIndex = "https://pypi.org/simple"

type Ecosystem struct{}

func New() Ecosystem {
	return Ecosystem{}
}

func (Ecosystem) Name() string { return "pdm" }

func (Ecosystem) OSVEcosystem() string { return "PyPI" }

func (Ecosystem) Detect(path string) bool {
	return core.FileExists(core.Join(path, lockfileName))
}

func (Ecosystem) Dependencies(path string) ([]core.Dependency, error) {
	raw, err := os.ReadFile(core.Join(path, lockfileName))
	if err != nil {
		return nil, err
	}

	var lock pdmLock
	if err := toml.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}

	sources := configuredSources(path)
	var deps []core.Dependency
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		kind, registry := classify(pkg, sources)
		for _, file := range files(pkg) {
			dep := core.Dependency{
				Ecosystem:  "pypi",
				Resolver:   "pdm",
				Registry:   registry,
				SourceKind: kind,
				Name:       pkg.Name,
				Version:    pkg.Version,
				Filename:   file.Name,
				Digest:     core.NormalizeDigest(file.Hash),
			}
			switch kind {
			case core.SourceGit:
				dep.Artifact = core.RemoteLocation(pkg.Git)
				dep.Resolved = pkg.Revision
			case core.SourceURL:
				dep.Artifact = core.RemoteLocation(pkg.URL)
			}
			deps = append(deps, dep)
		}
	}
	return deps, nil
}

type pdmLock struct {
	Package []pdmPackage `toml:"package"`
}

type pdmPackage struct {
	Name     string    `toml:"name"`
	Version  string    `toml:"version"`
	Path     string    `toml:"path"`
	URL      string    `toml:"url"`
	Git      string    `toml:"git"`
	Revision string    `toml:"revision"`
	Files    []pdmFile `toml:"files"`
}

type pdmFile struct {
	File string `toml:"file"`
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
}

type hashedFile struct {
	Name string
	Hash string
}

func files(pkg pdmPackage) []hashedFile {
	var out []hashedFile
	for _, file := range pkg.Files {
		if file.Hash == "" && file.File == "" {
			continue
		}
		out = append(out, hashedFile{Name: file.File, Hash: file.Hash})
	}
	if len(out) == 0 {
		return []hashedFile{{}}
	}
	return out
}

func classify(pkg pdmPackage, sources []string) (kind, registry string) {
	switch {
	case pkg.Path != "":
		return core.SourceFile, ""
	case pkg.Git != "":
		return core.SourceGit, ""
	case pkg.URL != "":
		return core.SourceURL, ""
	default:
		return core.SourceRegistry, registryOf(pkg, sources)
	}
}

func registryOf(pkg pdmPackage, sources []string) string {
	var urls []string
	for _, file := range pkg.Files {
		if file.URL != "" {
			urls = append(urls, file.URL)
		}
	}
	if len(urls) > 0 {
		return network.Provenance("pypi", urls)
	}
	return network.Provenance("pypi", sources)
}

func configuredSources(project string) []string {
	cfg := loadPDMConfig(project)
	var urls []string
	namedPypi := false
	for _, src := range cfg.sources {
		if strings.EqualFold(src.name, "pypi") {
			namedPypi = true
			break
		}
	}
	if !namedPypi {
		pypi := cfg.pypiURL
		if pypi == "" {
			pypi = defaultIndex
		}
		urls = append(urls, pypi)
	}
	for _, src := range cfg.sources {
		if src.url != "" {
			urls = append(urls, src.url)
		}
	}
	if !cfg.ignoreStored {
		urls = append(urls, cfg.extra...)
	}
	return urls
}

type pdmSource struct {
	name string
	url  string
}

type pdmCfg struct {
	pypiURL      string
	ignoreStored bool
	extra        []string
	sources      []pdmSource
}

func loadPDMConfig(project string) pdmCfg {
	cfg := pdmCfg{}
	for _, path := range siteConfigFiles() {
		applyConfigFile(&cfg, path)
	}
	for _, path := range userConfigFiles() {
		applyConfigFile(&cfg, path)
	}
	for _, dir := range dirsFromRoot(project) {
		applyConfigFile(&cfg, filepath.Join(dir, "pdm.toml"))
		cfg.sources = append(cfg.sources, pyprojectSources(filepath.Join(dir, "pyproject.toml"))...)
	}
	if v := strings.TrimSpace(os.Getenv("PDM_PYPI_URL")); v != "" {
		cfg.pypiURL = v
	}
	return cfg
}

func siteConfigFiles() []string {
	var paths []string
	if dirs := os.Getenv("XDG_CONFIG_DIRS"); dirs != "" {
		for _, dir := range strings.Split(dirs, ":") {
			if dir == "" {
				continue
			}
			paths = append(paths, filepath.Join(dir, "pdm", "config.toml"))
		}
	}
	if prog := os.Getenv("ProgramData"); prog != "" {
		paths = append(paths, filepath.Join(prog, "pdm", "pdm", "config.toml"))
	}
	return append(paths,
		"/etc/xdg/pdm/config.toml",
		"/Library/Application Support/pdm/config.toml",
	)
}

func userConfigFiles() []string {
	var paths []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "pdm", "config.toml"))
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		paths = append(paths, filepath.Join(local, "pdm", "pdm", "config.toml"))
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return paths
	}
	return append(paths,
		filepath.Join(home, ".config", "pdm", "config.toml"),
		filepath.Join(home, "Library", "Application Support", "pdm", "config.toml"),
		filepath.Join(home, "AppData", "Local", "pdm", "pdm", "config.toml"),
	)
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

func applyConfigFile(cfg *pdmCfg, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var parsed map[string]any
	if toml.Unmarshal(raw, &parsed) != nil {
		return
	}
	pypi, _ := parsed["pypi"].(map[string]any)
	if pypi == nil {
		return
	}
	if url := stringValue(pypi["url"]); url != "" {
		cfg.pypiURL = url
	}
	if ignore, ok := boolValue(pypi["ignore_stored_index"]); ok {
		cfg.ignoreStored = ignore
	}
	for name, value := range pypi {
		if name == "url" || name == "verify_ssl" || name == "username" || name == "password" || name == "ca_certs" || name == "client_cert" || name == "client_key" || name == "json_api" || name == "ignore_stored_index" {
			continue
		}
		sub, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if url := stringValue(sub["url"]); url != "" {
			cfg.extra = append(cfg.extra, url)
		}
	}
}

func pyprojectSources(path string) []pdmSource {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var parsed struct {
		Tool struct {
			PDM struct {
				Source []struct {
					Name string `toml:"name"`
					URL  string `toml:"url"`
				} `toml:"source"`
			} `toml:"pdm"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(raw, &parsed) != nil {
		return nil
	}
	var out []pdmSource
	for _, src := range parsed.Tool.PDM.Source {
		url := strings.TrimSpace(src.URL)
		if url == "" {
			continue
		}
		out = append(out, pdmSource{name: strings.TrimSpace(src.Name), url: url})
	}
	return out
}

func stringValue(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func boolValue(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}
