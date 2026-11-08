package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/workspace"
	"github.com/spf13/cobra"
)

// recursiveCommands run once per project under the path when --recursive is given.
var recursiveCommands = map[string]bool{"lock": true, "scan": true, "diff": true, "verify": true, "audit": true}

// withRecursive adds --recursive to the commands that work on one project. The command
// then runs once for each project found under the path, each with its own securock.lock,
// and exits with the worst result: an error beats a trust failure, which beats success.
// Every project is run even after one fails, so one report shows all of them.
func withRecursive(opts *options, root *cobra.Command) {
	for _, cmd := range root.Commands() {
		if !recursiveCommands[cmd.Name()] {
			continue
		}
		run := cmd.RunE
		cmd.Flags().BoolVarP(&opts.recursive, "recursive", "r", false, "run for every project under the path that has a supported lockfile, each with its own securock.lock")
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			if !opts.recursive {
				return run(cmd, args)
			}
			return runEach(cmd, opts, args, run)
		}
	}
}

func runEach(cmd *cobra.Command, opts *options, args []string, run func(*cobra.Command, []string) error) error {
	// Several reports in one stream are only readable as text. JSON, SARIF and JUnit would
	// be a sequence of documents no parser accepts, so they are refused instead.
	format := strings.ToLower(opts.format)
	if format != "text" && format != "" && format != "markdown" && format != "md" {
		return opErr(fmt.Errorf("--recursive supports --format text or markdown, not %q: run once per project for machine-readable output", opts.format))
	}
	root := projectPath(args)
	dirs, err := workspace.Discover(root)
	if err != nil {
		return opErr(err)
	}
	if len(dirs) == 0 {
		return opErr(fmt.Errorf("no supported lockfile found under %s", root))
	}

	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	var worst error
	failed := 0
	for i, dir := range dirs {
		if i > 0 {
			fmt.Fprintln(out)
		}
		if format == "markdown" || format == "md" {
			fmt.Fprintf(out, "# `%s`\n\n", dir)
		} else {
			fmt.Fprintf(out, "== %s ==\n", dir)
		}
		err := run(cmd, []string{filepath.Join(root, filepath.FromSlash(dir))})
		if err == nil {
			continue
		}
		failed++
		fmt.Fprintf(errOut, "%s: %v\n", dir, err)
		if worst == nil || exitCode(err) > exitCode(worst) {
			worst = err
		}
	}
	if worst == nil {
		return nil
	}
	return exitError{code: exitCode(worst), msg: fmt.Sprintf("%d of %d projects failed", failed, len(dirs))}
}

// exitCode is the exit status an error asks for; an error that names none is a failure.
func exitCode(err error) int {
	var e exitError
	if asExit(err, &e) {
		return e.code
	}
	return exitFail
}
