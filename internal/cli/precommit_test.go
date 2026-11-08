package cli_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cli"
	"gopkg.in/yaml.v3"
)

type preCommitHook struct {
	ID            string `yaml:"id"`
	Entry         string `yaml:"entry"`
	Language      string `yaml:"language"`
	PassFilenames bool   `yaml:"pass_filenames"`
	Files         string `yaml:"files"`
}

func readPreCommitHooks(t *testing.T) []preCommitHook {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks []preCommitHook
	if err := yaml.Unmarshal(raw, &hooks); err != nil {
		t.Fatal(err)
	}
	return hooks
}

// Every lockfile a resolver reads, so a change to one of them runs the hooks.
var resolverLockfiles = []string{
	"package-lock.json", "package.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
	"deno.lock", "Cargo.lock", "go.mod", "go.sum", "uv.lock", "poetry.lock", "pdm.lock",
	"Pipfile.lock", "composer.lock", "Gemfile.lock", "packages.lock.json", "Package.resolved",
	"Podfile.lock", "conan.lock", "renv.lock", "Manifest.toml", "cabal.project.freeze",
	"pubspec.lock", "mix.lock", "gradle.lockfile",
}

func TestPreCommitHooksRunRealCommands(t *testing.T) {
	hooks := readPreCommitHooks(t)
	if len(hooks) == 0 {
		t.Fatal("no hooks defined")
	}
	for _, h := range hooks {
		t.Run(h.ID, func(t *testing.T) {
			fields := strings.Fields(h.Entry)
			if len(fields) < 2 || fields[0] != "securock" {
				t.Fatalf("entry %q should be a securock command", h.Entry)
			}
			sub, _, err := cli.NewRoot("test", "none", "unknown").Find(fields[1:])
			if err != nil || sub.Name() != fields[1] {
				t.Fatalf("entry %q: %q is not a securock command", h.Entry, fields[1])
			}
			if h.Language != "golang" {
				t.Fatalf("language = %q, want golang so pre-commit builds the CLI", h.Language)
			}
			if h.PassFilenames {
				t.Fatal("securock checks the whole project, not the staged files")
			}
			re, err := regexp.Compile(h.Files)
			if err != nil {
				t.Fatalf("files pattern: %v", err)
			}
			names := append([]string{"securock.lock", ".securock/exceptions.yaml"}, resolverLockfiles...)
			for _, name := range names {
				if h.ID == "securock-audit" && name == "package.json" {
					continue // audit reads findings from the lockfile, not the manifest
				}
				for _, path := range []string{name, "services/api/" + name} {
					if !re.MatchString(path) {
						t.Errorf("%s does not run for %s", h.ID, path)
					}
				}
			}
			for _, path := range []string{"main.go", "README.md", "notpackage-lock.json", "go.summary"} {
				if re.MatchString(path) {
					t.Errorf("%s should not run for %s", h.ID, path)
				}
			}
		})
	}
}
