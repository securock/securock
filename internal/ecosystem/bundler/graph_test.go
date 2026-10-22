package bundler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/ecosystem/bundler"
	"github.com/securock/securock/internal/ecosystem/core"
)

const gemfileLock = `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)
      rack-session (>= 2.0.0)
    rack-session (2.0.0)
      rack (>= 3.0.0)
    rails (7.1.0)
      rack
      concurrent-ruby (~> 1.0)
    concurrent-ruby (1.2.0)
    rspec (3.12.0)
      rspec-core (~> 3.12.0)
      concurrent-ruby
    rspec-core (3.12.0)
    pry (0.14.0)
    both (1.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  both
  pry
  rails (~> 7.1)
  rspec

BUNDLED WITH
   2.5.11
`

func load(t *testing.T, files map[string]string) map[string]core.Dependency {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list, err := bundler.New().Dependencies(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]core.Dependency{}
	for _, dep := range list {
		out[dep.Name] = dep
	}
	return out
}

func TestGemfileGroupsDecideScope(t *testing.T) {
	deps := load(t, map[string]string{
		"Gemfile.lock": gemfileLock,
		"Gemfile": `source "https://rubygems.org"

gem "rails", "~> 7.1"
gem "both"

group :development, :test do
  gem "rspec"
  gem "pry"
  gem "both"
end

platforms :jruby do
  gem "jdbc"
end
`,
	})
	want := map[string]string{
		"rails": core.ScopeRuntime, "rack": core.ScopeRuntime, "rack-session": core.ScopeRuntime, "concurrent-ruby": core.ScopeRuntime,
		"rspec": core.ScopeDev, "rspec-core": core.ScopeDev, "pry": core.ScopeDev,
		// Listed at the top level and in a dev group: needed at runtime.
		"both": core.ScopeRuntime,
	}
	for name, scope := range want {
		if deps[name].Scope != scope {
			t.Errorf("%s = %q, want %q", name, deps[name].Scope, scope)
		}
	}
	if got := deps["rails"].DependsOn; len(got) != 2 || got[0] != "rubygems:concurrent-ruby@1.2.0" || got[1] != "rubygems:rack@3.0.8" {
		t.Errorf("rails edges = %v", got)
	}
}

func TestInlineGroupOptionAndNestedBlocks(t *testing.T) {
	deps := load(t, map[string]string{
		"Gemfile.lock": gemfileLock,
		"Gemfile": `gem "rails"
gem "rspec", group: :test
gem "pry", :group => [:development]

if ENV["X"]
  gem "both", groups: [:test, :production]
end
`,
	})
	if deps["rspec"].Scope != core.ScopeDev || deps["pry"].Scope != core.ScopeDev {
		t.Errorf("inline groups: rspec = %q, pry = %q", deps["rspec"].Scope, deps["pry"].Scope)
	}
	if deps["both"].Scope != core.ScopeRuntime {
		t.Errorf("a gem also in a non-development group is runtime, got %q", deps["both"].Scope)
	}
}

func TestWithoutGemfileDirectDependenciesAreRuntime(t *testing.T) {
	deps := load(t, map[string]string{"Gemfile.lock": gemfileLock})
	for _, name := range []string{"rails", "rspec", "pry", "rack", "rspec-core"} {
		if deps[name].Scope != core.ScopeRuntime {
			t.Errorf("%s = %q, want runtime", name, deps[name].Scope)
		}
	}
}
