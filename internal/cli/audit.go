package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newAuditCommand(opts *options) *cobra.Command {
	var failOn, minAge string
	cmd := &cobra.Command{
		Use:   "audit [path]",
		Short: "Audit dependencies and report findings by severity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			cooldown, err := parseAge(minAge)
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
				Path:         projectPath(args),
				Offline:      opts.offline,
				Network:      net,
				Policy:       pol,
				Reachability: opts.reachability,
			})
			if err != nil {
				return opErr(err)
			}

			path := projectPath(args)
			accepted, err := exceptions.Load(exceptions.Path(path, opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			report := exceptions.Apply(audit.RunWith(result.Document, audit.Options{MinReleaseAge: cooldown}), accepted, time.Now().UTC()).WithLocation(reportLocation(path, opts.lockPath))
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
	cmd.Flags().StringVar(&minAge, "min-release-age", "", "report releases published more recently than this as high findings: a number of days such as 7d, or a duration such as 72h (npm and PyPI)")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity: critical, high, medium, low, or info")
	return cmd
}

// parseAge reads a minimum release age: empty (off), a day count such as 7d, or a Go duration.
func parseAge(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("--min-release-age %q: use a number of days such as 7d, or a duration such as 72h", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("--min-release-age %q: use a number of days such as 7d, or a duration such as 72h", s)
	}
	return d, nil
}
