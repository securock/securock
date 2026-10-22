package cli

import (
	"github.com/securock/securock/internal/doctor"
	"github.com/securock/securock/internal/finding"
	"github.com/spf13/cobra"
)

func newDoctorCommand(opts *options) *cobra.Command {
	var failOn string
	cmd := &cobra.Command{
		Use:   "doctor [path]",
		Short: "Check the project setup for security problems",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			report := doctor.Run(doctor.Options{
				Root:       projectPath(args),
				LockPath:   opts.lockPath,
				PolicyPath: opts.policy,
				Profile:    opts.profile,

				ExceptionsPath: opts.exceptions,
			}).WithLocation(reportLocation(projectPath(args), opts.lockPath))
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
