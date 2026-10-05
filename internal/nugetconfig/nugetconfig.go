package nugetconfig

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// Sources returns the package sources NuGet would restore from. Sources turned
// off in disabledPackageSources are dropped.
func Sources(project string) []string {
	var sources []source
	disabled := map[string]bool{}
	var applied []os.FileInfo
	applyFile := func(path string) {
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
		sources = apply(sources, disabled, path)
	}

	for _, path := range machineConfigs() {
		applyFile(path)
	}
	for _, path := range userConfigs() {
		applyFile(path)
	}
	for _, dir := range dirsFromRoot(project) {
		if path := configIn(dir); path != "" {
			applyFile(path)
		}
	}
	var out []string
	for _, src := range sources {
		if !disabled[strings.ToLower(src.key)] {
			out = append(out, src.value)
		}
	}
	return out
}

type source struct {
	key   string
	value string
}

// Overridden reports whether MSBuild properties near the project replace the
// configured sources, in which case the NuGet config no longer proves origin.
func Overridden(project string) bool {
	for _, dir := range dirsFromRoot(project) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !msbuildFile(e.Name(), dir == filepath.Clean(projectAbs(project))) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			text := strings.ToLower(string(raw))
			for _, prop := range []string{"restoresources", "restoreadditionalprojectsources", "restorefallbackfolders"} {
				if strings.Contains(text, prop) {
					return true
				}
			}
		}
	}
	return false
}

func projectAbs(project string) string {
	abs, err := filepath.Abs(project)
	if err != nil {
		return project
	}
	return abs
}

func msbuildFile(name string, inProject bool) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "directory.build.props", "directory.build.targets", "directory.packages.props":
		return true
	}
	if !inProject {
		return false
	}
	for _, ext := range []string{".csproj", ".fsproj", ".vbproj", ".props", ".targets"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func machineConfigs() []string {
	var dirs []string
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles"} {
		if v := os.Getenv(env); v != "" {
			dirs = append(dirs, filepath.Join(v, "NuGet", "Config"))
		}
	}
	dirs = append(dirs,
		"/etc/opt/NuGet/Config",
		"/usr/local/share/NuGet/Config",
	)
	var paths []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".config") {
				continue
			}
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths
}

func userConfigs() []string {
	var paths []string
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		paths = append(paths, filepath.Join(appdata, "NuGet", "NuGet.Config"))
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return paths
	}
	return append(paths,
		filepath.Join(home, ".nuget", "NuGet", "NuGet.Config"),
		filepath.Join(home, ".config", "NuGet", "NuGet.Config"),
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

func configIn(dir string) string {
	var first string
	var firstInfo os.FileInfo
	for _, name := range []string{"nuget.config", "NuGet.Config"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if first != "" && os.SameFile(firstInfo, info) {
			continue
		}
		if first == "" {
			first, firstInfo = path, info
		}
	}
	return first
}

func apply(sources []source, disabled map[string]bool, path string) []source {
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
		sources = append(sources, source{key: strings.TrimSpace(add.Key), value: value})
	}
	for _, add := range cfg.Disabled.Add {
		key := strings.ToLower(strings.TrimSpace(add.Key))
		if key == "" {
			continue
		}
		disabled[key] = strings.EqualFold(strings.TrimSpace(add.Value), "true")
	}
	return sources
}

type nugetFile struct {
	PackageSources struct {
		Clear *struct{} `xml:"clear"`
		Add   []struct {
			Key   string `xml:"key,attr"`
			Value string `xml:"value,attr"`
		} `xml:"add"`
	} `xml:"packageSources"`
	Disabled struct {
		Add []struct {
			Key   string `xml:"key,attr"`
			Value string `xml:"value,attr"`
		} `xml:"add"`
	} `xml:"disabledPackageSources"`
}
