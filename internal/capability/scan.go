package capability

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

const maxBehaviorEntries = 64

var (
	reNetwork = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"](?:node:)?(?:http|https|net|dns|tls|dgram|undici)['"]\s*\)|from\s+['"](?:node:)?(?:http|https|net|dns|tls|dgram|undici)['"]|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b)`)
	reFSRead  = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"](?:node:)?(?:fs|fs/promises)['"]\s*\)|from\s+['"](?:node:)?(?:fs|fs/promises)['"]|\b(?:readFile(?:Sync)?|readdir(?:Sync)?|createReadStream|exists(?:Sync)?|stat(?:Sync)?|access(?:Sync)?)\s*\()`)
	reFSWrite = regexp.MustCompile(`(?i)\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|rmdir(?:Sync)?|mkdir(?:Sync)?|rename(?:Sync)?|copyFile(?:Sync)?|createWriteStream|truncate(?:Sync)?|chmod(?:Sync)?|chown(?:Sync)?)\s*\(`)
	reEnv     = regexp.MustCompile(`\bprocess\.env\b`)
	reShell   = regexp.MustCompile(`(?i)(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|\b(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?|fork)\s*\()`)

	reURLHost   = regexp.MustCompile(`(?i)https?://([a-z0-9._:-]+)`)
	reEnvName   = regexp.MustCompile(`process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\])`)
	reCommand   = regexp.MustCompile(`(?i)(?:exec(?:File)?(?:Sync)?|spawn(?:Sync)?)\s*\(\s*['"]([^'"]+)['"]`)
	reReadPath  = regexp.MustCompile(`(?i)(?:readFile(?:Sync)?|readdir(?:Sync)?|createReadStream|exists(?:Sync)?|stat(?:Sync)?|access(?:Sync)?)\s*\(\s*['"]([^'"]+)['"]`)
	reWritePath = regexp.MustCompile(`(?i)(?:writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|rmdir(?:Sync)?|mkdir(?:Sync)?|rename(?:Sync)?|copyFile(?:Sync)?|createWriteStream|truncate(?:Sync)?|chmod(?:Sync)?|chown(?:Sync)?)\s*\(\s*['"]([^'"]+)['"]`)

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

	Hosts      []string
	FilesRead  []string
	FilesWrite []string
	Commands   []string
	EnvVars    []string
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

func Behavior(f Findings) lockfile.BehaviorEvidence {
	out := lockfile.BehaviorEvidence{
		State:       lockfile.CapChecked,
		Network:     limitSorted(f.Hosts),
		Commands:    limitSorted(f.Commands),
		Environment: limitSorted(f.EnvVars),
	}
	read := limitSorted(f.FilesRead)
	write := limitSorted(f.FilesWrite)
	if len(read) > 0 || len(write) > 0 {
		out.Files = &lockfile.BehaviorFiles{Read: read, Write: write}
	}
	return out
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

	for _, m := range reURLHost.FindAllStringSubmatch(text, -1) {
		if host := normalizeHost(m[1]); host != "" {
			f.Hosts = append(f.Hosts, host)
			f.Network = true
		}
	}
	for _, m := range reEnvName.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name != "" {
			f.EnvVars = append(f.EnvVars, name)
			f.Environment = true
		}
	}
	for _, m := range reCommand.FindAllStringSubmatch(text, -1) {
		if cmd := normalizeCommand(m[1]); cmd != "" {
			f.Commands = append(f.Commands, cmd)
			f.Shell = true
		}
	}
	for _, m := range reReadPath.FindAllStringSubmatch(text, -1) {
		if path := normalizePath(m[1]); path != "" {
			f.FilesRead = append(f.FilesRead, path)
			if f.Filesystem != lockfile.FilesystemWrite {
				f.Filesystem = lockfile.FilesystemRead
			}
		}
	}
	for _, m := range reWritePath.FindAllStringSubmatch(text, -1) {
		if path := normalizePath(m[1]); path != "" {
			f.FilesWrite = append(f.FilesWrite, path)
			f.Filesystem = lockfile.FilesystemWrite
		}
	}
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || strings.Contains(raw, "${") || strings.Contains(raw, "`") {
		return ""
	}
	if strings.Contains(raw, ":") {
		if u, err := url.Parse("https://" + raw); err == nil && u.Hostname() != "" {
			raw = u.Hostname()
		} else if host, _, ok := strings.Cut(raw, ":"); ok {
			raw = host
		}
	}
	if !strings.Contains(raw, ".") && raw != "localhost" {
		return ""
	}
	return raw
}

func normalizeCommand(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "${") {
		return ""
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	cmd := fields[0]
	if i := strings.LastIndex(cmd, "/"); i >= 0 {
		cmd = cmd[i+1:]
	}
	return cmd
}

func normalizePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "${") || len(raw) > 200 {
		return ""
	}
	return raw
}

func limitSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	cp := slices.Clone(in)
	slices.Sort(cp)
	cp = slices.Compact(cp)
	out := cp[:0]
	for _, s := range cp {
		if s == "" {
			continue
		}
		out = append(out, s)
		if len(out) >= maxBehaviorEntries {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
