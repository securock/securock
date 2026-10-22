package mix_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/core"
	"github.com/securock/securock/internal/ecosystem/mix"
)

const lock = `%{
  "phoenix": {:hex, :phoenix, "1.7.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [{:plug, "~> 1.14", [hex: :plug, repo: "hexpm", optional: false]}, {:telemetry, "~> 1.0", [hex: :telemetry, repo: "hexpm", optional: false]}, {:absent, ">= 0.0.0", [hex: :absent, repo: "hexpm", optional: true]}], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
  "plug": {:hex, :plug, "1.14.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [{:telemetry, "~> 1.0", [hex: :telemetry, repo: "hexpm", optional: false]}], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
  "telemetry": {:hex, :telemetry, "1.2.1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:rebar3], [], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
  "credo": {:hex, :credo, "1.7.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [{:jason, "~> 1.0", [hex: :jason, repo: "hexpm", optional: false]}], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
  "jason": {:hex, :jason, "1.4.4", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
  "loose": {:hex, :loose, "0.1.0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", [:mix], [], "hexpm", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
}
`

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
	list, err := mix.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range list {
		out[dep.Name] = dep
	}
	return out
}

func TestScopeFromMixExs(t *testing.T) {
	deps := load(t, map[string]string{
		"mix.lock": lock,
		"mix.exs": `defmodule App.MixProject do
  use Mix.Project

  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:jason, "~> 1.0", only: :test}
    ]
  end
end
`,
	})
	want := map[string]string{
		"phoenix": core.ScopeRuntime, "plug": core.ScopeRuntime, "telemetry": core.ScopeRuntime,
		"credo": core.ScopeDev,
		// jason is limited to test directly, and only credo (a dev tool) needs it besides.
		"jason": core.ScopeDev,
		"loose": "",
	}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
	// Edges to packages missing from the lockfile, such as an uninstalled optional one, are dropped.
	if got := deps["phoenix"].DependsOn; len(got) != 2 || got[0] != "hex:plug@1.14.0" || got[1] != "hex:telemetry@1.2.1" {
		t.Errorf("phoenix edges = %v", got)
	}
}

func TestOnlyProdIsRuntime(t *testing.T) {
	deps := load(t, map[string]string{
		"mix.lock": lock,
		"mix.exs":  "defp deps do\n  [{:jason, \"~> 1.0\", only: [:dev, :prod]}, {:loose, \"~> 0.1\", only: [:test]}]\nend\n",
	})
	if deps["jason"].Scope != core.ScopeRuntime || deps["loose"].Scope != core.ScopeDev {
		t.Fatalf("jason = %q, loose = %q", deps["jason"].Scope, deps["loose"].Scope)
	}
}

func TestUmbrellaAppsAndMissingMixExs(t *testing.T) {
	deps := load(t, map[string]string{
		"mix.lock":         lock,
		"apps/web/mix.exs": "defp deps do\n  [{:phoenix, \"~> 1.7\"}]\nend\n",
	})
	if deps["phoenix"].Scope != core.ScopeRuntime || deps["credo"].Scope != "" {
		t.Fatalf("phoenix = %q, credo = %q", deps["phoenix"].Scope, deps["credo"].Scope)
	}

	none := load(t, map[string]string{"mix.lock": lock})
	if none["phoenix"].Scope != "" {
		t.Fatalf("without mix.exs scopes are unknown, got %q", none["phoenix"].Scope)
	}
}
