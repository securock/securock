package cli

import (
	"fmt"

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
				return err
			}

			lockPath := lock.Path(path, opts.lockPath)
			locked, err := lock.Read(lockPath)
			if err != nil {
				return err
			}

			result, err := scanner.Scan(cmd.Context(), scanner.Options{
				Path:    path,
				Offline: opts.offline,
				Policy:  pol,
			})
			if err != nil {
				return err
			}

			got := diff.Compare(locked, result.Document)
			diff.Write(cmd.OutOrStdout(), got)
			if opts.noFail || !got.TrustDrift() {
				return nil
			}
			return fmt.Errorf("trust drift detected")
		},
	}
}
