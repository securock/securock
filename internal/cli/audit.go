package cli

import (
	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newAuditCommand(opts *options) *cobra.Command {
	var failOn string
	cmd := &cobra.Command{
		Use:   "audit [path]",
		Short: "Audit dependencies and report findings by severity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			pol, err := policy.LoadWithProfile(opts.policy, opts.profile)
			if err != nil {
				return opErr(err)
			}
			net, err := scanOptions(opts, pol)
			if err != nil {
				return err
			}
			result, err := scanner.Scan(cmd.Context(), scanner.Options{
				Path:    projectPath(args),
				Offline: opts.offline,
				Network: net,
				Policy:  pol,
			})
			if err != nil {
				return opErr(err)
			}

			report := audit.Run(result.Document).WithLocation(reportLocation(projectPath(args), opts.lockPath))
			if err := finding.Write(cmd.OutOrStdout(), report, opts.format); err != nil {
				return opErr(err)
			}
			if opts.noFail {
				return nil
			}
			if n := report.AtLeast(threshold); n > 0 {
				return trustErr("findings at or above %s: %d", threshold, n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity: critical, high, medium, low, or info")
	return cmd
}
