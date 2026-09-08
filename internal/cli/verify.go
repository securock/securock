package cli

import (
	"fmt"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/securock/securock/internal/verify"
	"github.com/spf13/cobra"
)

func newVerifyCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "verify [path]",
		Short: "Verify the current project against securock.lock",
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

			findings := verify.Compare(locked, result.Document)
			if len(findings.Findings) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "ok  %d artifacts\n", len(result.Document.Artifacts))
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), findings.Error())
			if opts.noFail {
				return nil
			}
			return fmt.Errorf("verify failed (%d findings)", len(findings.Findings))
		},
	}
}
