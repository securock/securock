package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cli"
	"github.com/securock/securock/schemas"
)

func TestProgressKeepsCapturedReportsClean(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, "package main\nfunc main() {}\n")
	for _, command := range []string{"sast", "security", "chain", "scan"} {
		for _, format := range []string{"text", "json", "sarif"} {
			t.Run(command+"/"+format, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				root := cli.NewRoot("test", "none", "unknown")
				root.SetOut(&stdout)
				root.SetErr(&stderr)
				root.SetArgs([]string{command, dir, "--offline", "--no-fail", "--format", format})
				// scan needs a package-manager lockfile; other commands need none.
				if command == "scan" {
					root.SetArgs([]string{command, "../ecosystem/npm/testdata", "--offline", "--no-fail", "--format", format})
				}
				if err := root.Execute(); err != nil {
					t.Fatal(err)
				}
				if stderr.Len() != 0 || strings.ContainsAny(stdout.String(), "\r\x1b") {
					t.Fatalf("progress leaked into captured output: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				if format == "json" && command != "chain" {
					if err := schemas.Validate(command+"-report.schema.json", stdout.Bytes()); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestNoProgressFlag(t *testing.T) {
	isolateHome(t)
	dir := writeGo(t, "package main\nfunc main() {}\n")
	for _, command := range []string{"sast", "security"} {
		plain := runCLI(t, command, dir, "--offline", "--no-fail")
		hidden := runCLI(t, command, dir, "--offline", "--no-fail", "--no-progress")
		if !bytes.Equal(plain, hidden) {
			t.Fatalf("--no-progress changed the report: %s", hidden)
		}
	}
}
