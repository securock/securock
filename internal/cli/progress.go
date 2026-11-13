package cli

import (
	"io"
	"os"
	"strings"

	"github.com/securock/securock/internal/progress"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// These commands perform source or dependency analysis. Other commands (including
// servers and nested orchestration) must not acquire an interactive status line.
var progressCommands = map[string]bool{
	"securock": true, "security": true, "sast": true, "chain": true,
	"scan": true, "audit": true, "lock": true, "verify": true, "diff": true,
	"update": true, "init": true, "explain": true, "graph": true, "remediate": true,
}

func withProgress(opts *options, root *cobra.Command) {
	wrap := func(cmd *cobra.Command) {
		run := cmd.RunE
		if run == nil || !progressCommands[cmd.Name()] {
			return
		}
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
			fd, ok := errOut.(interface{ Fd() uintptr })
			if opts.noProgress || !ok || !isTerminal(errOut) ||
				(opts.output == "" && !isTerminal(out)) ||
				os.Getenv("TERM") == "dumb" || os.Getenv("CI") != "" ||
				(strings.ToLower(opts.format) != "text" && opts.format != "") {
				return run(cmd, args)
			}
			d := progress.Start(errOut, "securock: starting analysis", func() int {
				width, _, _ := term.GetSize(int(fd.Fd()))
				return width
			})
			ctx := cmd.Context()
			cmd.SetContext(progress.WithReporter(ctx, d.Update))
			// Clear before the first report or diagnostic, even if both streams go
			// to the same terminal. Restore writers/context for reused commands.
			cmd.SetOut(progressOutput{out, d})
			cmd.SetErr(progressOutput{errOut, d})
			defer func() {
				d.Stop()
				cmd.SetOut(out)
				cmd.SetErr(errOut)
				cmd.SetContext(ctx)
			}()
			return run(cmd, args)
		}
	}
	wrap(root)
	for _, cmd := range root.Commands() {
		wrap(cmd)
	}
}

type progressOutput struct {
	io.Writer
	display *progress.Display
}

func (w progressOutput) Write(p []byte) (int, error) {
	w.display.Stop()
	return w.Writer.Write(p)
}

func isTerminal(w io.Writer) bool {
	fd, ok := w.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(fd.Fd()))
}
