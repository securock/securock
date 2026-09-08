package cli

import (
	"fmt"

	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newLockCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "lock [path]",
		Short: "Write a language-agnostic securock.lock",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := projectPath(args)
			pol, err := policy.Load(opts.policy)
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

			out := lock.Path(path, opts.lockPath)
			if err := lock.Write(out, result.Document); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)

			_, untrusted, unknown := scanner.Summary(result.Document)
			if opts.noFail {
				return nil
			}
			if untrusted > 0 {
				return fmt.Errorf("untrusted artifacts: %d", untrusted)
			}
			if unknown > 0 {
				return fmt.Errorf("unknown artifacts: %d", unknown)
			}
			return nil
		},
	}
}
