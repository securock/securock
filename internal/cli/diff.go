package cli

import (
	"fmt"
	"strings"

	"github.com/securock/securock/internal/diff"
	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newDiffCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "diff [path]",
		Short: "Show trust drift against securock.lock",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := projectPath(args)
			pol, err := policy.Load(opts.policy)
			if err != nil {
				return opErr(err)
			}
			net, err := scanOptions(opts, pol)
			if err != nil {
				return err
			}

			lockPath := lock.Path(path, opts.lockPath)
			locked, err := lock.Read(lockPath)
			if err != nil {
				return opErr(err)
			}

			result, err := scanner.Scan(cmd.Context(), scanner.Options{
				Path:    path,
				Offline: opts.offline,
				Network: net,
				Policy:  pol,
			})
			if err != nil {
				return opErr(err)
			}

			got := diff.Compare(locked, result.Document)
			if err := writeDiff(cmd, got, opts.format); err != nil {
				return opErr(err)
			}
			if opts.noFail || !got.TrustDrift() {
				return nil
			}
			return trustErr("trust drift detected")
		},
	}
}

func writeDiff(cmd *cobra.Command, got diff.Result, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return diff.WriteJSON(cmd.OutOrStdout(), got)
	case "text", "":
		diff.Write(cmd.OutOrStdout(), got)
		return nil
	default:
		return opErr(fmt.Errorf("unsupported format %q", format))
	}
}
