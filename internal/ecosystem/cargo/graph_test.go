package cargo_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/cargo"
	"github.com/securock/securock/internal/ecosystem/core"
)

func crate(name, version string, deps ...string) string {
	out := `
[[package]]
name = "` + name + `"
version = "` + version + `"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
`
	if len(deps) > 0 {
		out += "dependencies = [\n"
		for _, d := range deps {
			out += `    "` + d + `",` + "\n"
		}
		out += "]\n"
	}
	return out
}

func load(t *testing.T, files map[string]string) map[string]core.Dependency {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list, err := cargo.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range list {
		out[core.Identity(dep)] = dep
	}
	return out
}

const lock = `version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "tokio 1.0.0", "criterion"]
` // workspace members have no source

func TestScopeFromManifestAndEdgesFromLock(t *testing.T) {
	deps := load(t, map[string]string{
		"Cargo.lock": lock +
			crate("serde", "1.0.210", "serde_derive") + crate("serde_derive", "1.0.210") +
			crate("tokio", "1.0.0", "mio") + crate("tokio", "0.1.0") + crate("mio", "0.8.0") +
			crate("criterion", "0.5.0", "serde 1.0.210 (registry+https://github.com/rust-lang/crates.io-index)", "walkdir") +
			crate("walkdir", "2.0.0") + crate("cc", "1.0.0") + crate("renamed-real", "3.0.0") + crate("loose", "0.1.0"),
		"Cargo.toml": `[package]
name = "app"

[dependencies]
serde = "1"
tokio = { version = "1", features = ["full"] }
alias = { package = "renamed-real", version = "3" }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1"

[target.'cfg(unix)'.dependencies]
mio = "0.8"
`,
	})
	want := map[string]string{
		"cargo:serde@1.0.210":        core.ScopeRuntime,
		"cargo:serde_derive@1.0.210": core.ScopeRuntime,
		"cargo:tokio@1.0.0":          core.ScopeRuntime,
		// Declared by name only, so every locked version of tokio counts.
		"cargo:tokio@0.1.0":        core.ScopeRuntime,
		"cargo:mio@0.8.0":          core.ScopeRuntime,
		"cargo:criterion@0.5.0":    core.ScopeDev,
		"cargo:walkdir@2.0.0":      core.ScopeDev,
		"cargo:cc@1.0.0":           core.ScopeRuntime,
		"cargo:renamed-real@3.0.0": core.ScopeRuntime,
		"cargo:loose@0.1.0":        "",
	}
	for id, scope := range want {
		dep, ok := deps[id]
		if !ok {
			t.Fatalf("%s not found", id)
		}
		if dep.Scope != scope {
			t.Errorf("%s scope = %q, want %q", id, dep.Scope, scope)
		}
	}
	// serde is a runtime dependency and also used by criterion: runtime wins.
	if got := deps["cargo:criterion@0.5.0"].DependsOn; len(got) != 2 || got[0] != "cargo:serde@1.0.210" || got[1] != "cargo:walkdir@2.0.0" {
		t.Errorf("criterion edges = %v", got)
	}
	if got := deps["cargo:tokio@1.0.0"].DependsOn; len(got) != 1 || got[0] != "cargo:mio@0.8.0" {
		t.Errorf("tokio edges = %v", got)
	}
}

func TestWorkspaceMembers(t *testing.T) {
	deps := load(t, map[string]string{
		"Cargo.lock":            "version = 3\n" + crate("a", "1.0.0") + crate("b", "1.0.0"),
		"Cargo.toml":            "[workspace]\nmembers = [\"crates/*\"]\n",
		"crates/one/Cargo.toml": "[package]\nname = \"one\"\n[dependencies]\na = \"1\"\n",
		"crates/two/Cargo.toml": "[package]\nname = \"two\"\n[dev-dependencies]\nb = \"1\"\n",
	})
	if deps["cargo:a@1.0.0"].Scope != core.ScopeRuntime || deps["cargo:b@1.0.0"].Scope != core.ScopeDev {
		t.Fatalf("scopes = %q, %q", deps["cargo:a@1.0.0"].Scope, deps["cargo:b@1.0.0"].Scope)
	}
}

func TestWithoutManifestScopesStayUnknown(t *testing.T) {
	deps := load(t, map[string]string{"Cargo.lock": lock + crate("serde", "1.0.210")})
	if got := deps["cargo:serde@1.0.210"].Scope; got != "" {
		t.Fatalf("scope = %q", got)
	}
}
