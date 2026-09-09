package nugetconfig_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/nugetconfig"
)

func isolate(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", home)
}

func TestSourcesUnknownWithoutConfig(t *testing.T) {
	isolate(t)
	if got := nugetconfig.Sources(t.TempDir()); len(got) != 0 {
		t.Fatalf("unproven sources = %#v", got)
	}
}

func TestSourcesFromProjectConfig(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	raw := `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="company" value="https://nuget.company.example/v3/index.json" />
  </packageSources>
</configuration>
`
	if err := os.WriteFile(filepath.Join(dir, "nuget.config"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got := nugetconfig.Sources(dir)
	if len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
}

func TestSourcesClearDropsUserConfig(t *testing.T) {
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
	dir := t.TempDir()
	raw := `<?xml version="1.0"?><configuration><packageSources><clear /><add key="company" value="https://nuget.company.example/v3/index.json" /></packageSources></configuration>`
	if err := os.WriteFile(filepath.Join(dir, "NuGet.Config"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got := nugetconfig.Sources(dir)
	if len(got) != 1 || got[0] != "https://nuget.company.example/v3/index.json" {
		t.Fatalf("got %#v", got)
	}
}
