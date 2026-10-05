package capability

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"regexp"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

var (
	reNetwork = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"](?:node:)?(?:http|https|net|dns|tls|dgram|undici)['"]\s*\)|from\s+['"](?:node:)?(?:http|https|net|dns|tls|dgram|undici)['"]|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b)`)
	reFSRead  = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"](?:node:)?(?:fs|fs/promises)['"]\s*\)|from\s+['"](?:node:)?(?:fs|fs/promises)['"]|\b(?:readFile(?:Sync)?|readdir(?:Sync)?|createReadStream|exists(?:Sync)?|stat(?:Sync)?|access(?:Sync)?)\s*\()`)
	reFSWrite = regexp.MustCompile(`(?i)\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|rmdir(?:Sync)?|mkdir(?:Sync)?|rename(?:Sync)?|copyFile(?:Sync)?|createWriteStream|truncate(?:Sync)?|chmod(?:Sync)?|chown(?:Sync)?)\s*\(`)
	reEnv     = regexp.MustCompile(`\bprocess\.env\b`)
	reShell   = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|\b(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?|fork)\s*\()`)

	nativeBuildDeps = []string{
		"node-gyp", "node-pre-gyp", "@mapbox/node-pre-gyp", "prebuild", "prebuild-install",
		"node-addon-api", "nan", "bindings",
	}
	installScriptNames = []string{"preinstall", "install", "postinstall"}
)

type Metadata struct {
	HasInstallScript bool
	Scripts          map[string]string
	Gypfile          bool
	Binary           bool
	Dependencies     map[string]string
	OptionalDeps     map[string]string
	BundledDeps      []string
	Files            []string
}

type Findings struct {
	Network        bool
	Filesystem     lockfile.FilesystemAccess
	Environment    bool
	Shell          bool
	NativeCode     bool
	InstallScripts bool
	ScannedSource  bool
}

func FromMetadata(meta Metadata) Findings {
	install := meta.HasInstallScript
	if !install {
		for _, name := range installScriptNames {
			if strings.TrimSpace(meta.Scripts[name]) != "" {
				install = true
				break
			}
		}
	}

	native := meta.Gypfile || meta.Binary
	if !native {
		native = depsContain(meta.Dependencies, nativeBuildDeps) ||
			depsContain(meta.OptionalDeps, nativeBuildDeps) ||
			namesContain(meta.BundledDeps, nativeBuildDeps) ||
			filesSuggestNative(meta.Files)
	}

	f := Findings{
		InstallScripts: install,
		NativeCode:     native,
		Shell:          install,
		Filesystem:     lockfile.FilesystemNone,
	}
	for _, body := range meta.Scripts {
		scanText(&f, body)
	}
	return f
}

func ScanSource(r io.Reader, f *Findings) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	f.ScannedSource = true
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.ToLower(hdr.Name)
		base := name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			base = name[i+1:]
		}
		switch {
		case strings.HasSuffix(base, ".node"), base == "binding.gyp":
			f.NativeCode = true
		case isScannableJS(base):
			const maxFile = 512 << 10
			limited := io.LimitReader(tr, maxFile+1)
			raw, err := io.ReadAll(limited)
			if err != nil {
				return err
			}
			if len(raw) > maxFile {
				continue
			}
			scanText(f, string(raw))
		}
	}
}

func Evidence(f Findings) lockfile.CapabilityEvidence {
	fs := f.Filesystem
	if fs == "" {
		fs = lockfile.FilesystemNone
	}
	return lockfile.CapabilityEvidence{
		State:          lockfile.CapChecked,
		Network:        lockfile.Bool(f.Network),
		Filesystem:     fs,
		Environment:    lockfile.Bool(f.Environment),
		Shell:          lockfile.Bool(f.Shell),
		NativeCode:     lockfile.Bool(f.NativeCode),
		InstallScripts: lockfile.Bool(f.InstallScripts),
	}
}

func scanText(f *Findings, text string) {
	if reNetwork.MatchString(text) {
		f.Network = true
	}
	if reEnv.MatchString(text) {
		f.Environment = true
	}
	if reShell.MatchString(text) {
		f.Shell = true
	}
	if reFSWrite.MatchString(text) {
		f.Filesystem = lockfile.FilesystemWrite
	} else if f.Filesystem != lockfile.FilesystemWrite && reFSRead.MatchString(text) {
		f.Filesystem = lockfile.FilesystemRead
	}
}

func isScannableJS(base string) bool {
	for _, ext := range []string{".js", ".mjs", ".cjs", ".ts", ".cts", ".mts"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

func depsContain(deps map[string]string, names []string) bool {
	for _, name := range names {
		if _, ok := deps[name]; ok {
			return true
		}
	}
	return false
}

func namesContain(values, names []string) bool {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	for _, name := range names {
		if _, ok := set[name]; ok {
			return true
		}
	}
	return false
}

func filesSuggestNative(files []string) bool {
	for _, f := range files {
		low := strings.ToLower(f)
		if strings.HasSuffix(low, ".node") || strings.HasSuffix(low, "binding.gyp") {
			return true
		}
	}
	return false
}
