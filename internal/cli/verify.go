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

func newVerifyCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "verify [path]",
		Short: "Verify the current project against securock.lock",
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
			if strings.ToLower(opts.format) == "json" {
				if err := diff.WriteJSON(cmd.OutOrStdout(), got); err != nil {
					return opErr(err)
				}
			} else if !got.TrustDrift() {
				fmt.Fprintf(cmd.OutOrStdout(), "ok  %d artifacts\n", len(result.Document.Artifacts))
			} else {
				diff.Write(cmd.OutOrStdout(), got)
			}
			if opts.noFail || !got.TrustDrift() {
				return nil
			}
			return trustErr("trust drift detected")
		},
	}
}
