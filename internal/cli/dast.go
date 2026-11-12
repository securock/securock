package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/securock/securock/internal/dast"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/policy"
	pkgpolicy "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
)

func validateDAST(targets []string, timeout time.Duration, net pkgpolicy.Network) error {
	if len(targets) == 0 {
		return nil
	}
	if net.ResolvedMode() != pkgpolicy.ModeAllowAll {
		return fmt.Errorf("DAST requires --network allow-all (or that mode in the policy); offline and public-only modes do not contact application targets")
	}
	if timeout <= 0 {
		return fmt.Errorf("DAST timeout must be positive")
	}
	for _, target := range targets {
		if _, err := dast.ValidateURL(target); err != nil {
			return err
		}
	}
	return nil
}

func scanDAST(ctx context.Context, targets []string, timeout time.Duration) ([]finding.Finding, error) {
	var found []finding.Finding
	var failures []error
	for _, target := range targets {
		report, err := dast.Scan(ctx, dast.Options{URL: target, Timeout: timeout})
		found = append(found, report.Findings...)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return found, errors.Join(failures...)
}

func newDASTCommand(opts *options) *cobra.Command {
	var failOn string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use: "dast URL...", Short: "Inspect live HTTP security headers, transport, and cookies",
		Long: `Inspect the explicitly supplied URLs using bounded GET requests. No crawling,
form submissions, injection payloads, or authenticated sessions are performed.
Only exact-origin redirects are followed, up to five per target. Requires the
allow-all network mode; offline and public-only modes make no target requests.
Missing defenses are configuration findings, not proof of exploitability.`,
		Args: cobra.MinimumNArgs(1),
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
			if err := validateDAST(args, timeout, net); err != nil {
				return opErr(err)
			}
			accepted, err := exceptions.Load(exceptions.Path(".", opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			found, scanErr := scanDAST(cmd.Context(), args, timeout)
			report := exceptions.Apply(finding.New("dast", found), accepted, time.Now().UTC())
			if err := finding.Write(cmd.OutOrStdout(), report, opts.format); err != nil {
				return opErr(err)
			}
			if scanErr != nil {
				return opErr(scanErr)
			}
			if !opts.noFail {
				if n := report.AtLeast(threshold); n > 0 {
					return trustErr("findings at or above %s: %d", threshold, n)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 at this severity: critical, high, medium, low, or info")
	cmd.Flags().DurationVar(&timeout, "timeout", dast.DefaultTimeout, "total request timeout per target, including redirects")
	return cmd
}
