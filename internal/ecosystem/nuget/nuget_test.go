package nuget_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/nuget"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
}

func TestDependencies(t *testing.T) {
	isolate(t)
	eco := nuget.New()
	if !eco.Detect("testdata") {
		t.Fatal("expected packages.lock.json to be detected")
	}
	deps, err := eco.Dependencies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1 (project refs skipped): %#v", len(deps), deps)
	}
	dep := deps[0]
	if dep.Ecosystem != "nuget" || dep.Resolver != "nuget" {
		t.Fatalf("ecosystem/resolver = %s/%s", dep.Ecosystem, dep.Resolver)
	}
	if dep.Name != "Newtonsoft.Json" || dep.Version != "13.0.3" {
		t.Fatalf("nuget pkg = %+v", dep)
	}
	if dep.SourceKind != core.SourceRegistry || dep.Registry != "" {
		t.Fatalf("unproven nuget registry = %+v", dep)
	}
	if dep.Digest != "sha512:ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff" {
		t.Fatalf("digest = %q", dep.Digest)
	}
}

func TestProvenanceFromNugetConfig(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `<?xml version="1.0"?><configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "nuget.config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://api.nuget.org" {
		t.Fatalf("public nuget = %#v", deps)
	}
}

func TestPrivateFeedUnknown(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `<?xml version="1.0"?><configuration><packageSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  <add key="company" value="https://nuget.company.example/v3/index.json" />
</packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "nuget.config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("mixed nuget feeds must be unknown: %#v", deps)
	}
}

func TestParentConfigMustNotLookPublic(t *testing.T) {
	isolate(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	userDir := filepath.Join(home, ".nuget", "NuGet")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	user := `<?xml version="1.0"?><configuration><packageSources><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(userDir, "NuGet.Config"), []byte(user), 0o644); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	project := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "packages.lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := `<?xml version="1.0"?><configuration><packageSources><add key="company" value="https://nuget.company.example/v3/index.json" /></packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(root, "NuGet.Config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	deps, err := nuget.New().Dependencies(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("parent private feed with user nuget.org must be unknown: %#v", deps)
	}
}

func writeProject(t *testing.T, dir, config string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "packages.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, "nuget.config"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnreadableSourceUnknown(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	writeProject(t, dir, `<?xml version="1.0"?><configuration><packageSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  <add key="local" value="./local-feed" />
</packageSources></configuration>`)
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("local feed next to nuget.org must be unknown: %#v", deps)
	}
}

func TestDisabledPrivateSourceIgnored(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	writeProject(t, dir, `<?xml version="1.0"?><configuration><packageSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  <add key="company" value="https://nuget.company.example/v3/index.json" />
</packageSources><disabledPackageSources><add key="company" value="true" /></disabledPackageSources></configuration>`)
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "https://api.nuget.org" {
		t.Fatalf("disabled feed must not taint provenance: %#v", deps)
	}
}

func TestMSBuildRestoreSourcesUnknown(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	writeProject(t, dir, `<?xml version="1.0"?><configuration><packageSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
</packageSources></configuration>`)
	props := `<Project><PropertyGroup><RestoreSources>https://nuget.company.example/v3/index.json</RestoreSources></PropertyGroup></Project>`
	if err := os.WriteFile(filepath.Join(dir, "Directory.Build.props"), []byte(props), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := nuget.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Registry != "" {
		t.Fatalf("msbuild source override must be unknown: %#v", deps)
	}
}
