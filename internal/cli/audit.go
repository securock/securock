package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/exploit"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/osv"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/securock/securock/internal/scorecard"
	"github.com/securock/securock/pkg/lockfile"
	pkgpolicy "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
)

func newAuditCommand(opts *options) *cobra.Command {
	var failOn, minAge string
	var prioritize bool
	var minScorecard float64
	var scorecardOn bool
	cmd := &cobra.Command{
		Use:   "audit [path]",
		Short: "Audit dependencies and report findings by severity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			if minScorecard < 0 || minScorecard > 10 {
				return opErr(fmt.Errorf("--min-scorecard %v: use a score from 0 to 10", minScorecard))
			}
			pol, err := policy.LoadWithProfile(opts.policy, opts.profile)
			if err != nil {
				return opErr(err)
			}
			cooldown, err := parseAge(minAge, pol.Rules.Health.MinReleaseAge)
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
			auditOpts := audit.Options{MinReleaseAge: cooldown, InternalNames: pol.Rules.Health.InternalNames}
			if prioritize {
				auditOpts.Signals, auditOpts.SignalsUnavailable = exploitSignals(cmd.Context(), net.Mode, result.Document)
			}
			if minScorecard > 0 || scorecardOn {
				auditOpts.MinScorecard = minScorecard
				auditOpts.ScorecardChecks = pol.Rules.Health.ScorecardChecks
				auditOpts.Scorecards, auditOpts.ScorecardUnchecked = scorecard.New().Collect(cmd.Context(), net, result.Document)
			}
			report := exceptions.Apply(audit.RunWith(result.Document, auditOpts), accepted, time.Now().UTC()).WithLocation(reportLocation(path, opts.lockPath))
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
	cmd.Flags().StringVar(&minAge, "min-release-age", "", "report releases published more recently than this as high findings (default: rules.health.min_release_age in the policy): a number of days such as 7d, or a duration such as 72h (npm and PyPI)")
	cmd.Flags().BoolVar(&scorecardOn, "scorecard", false, "look up OpenSSF Scorecards and apply rules.health.scorecard_checks from the policy; sends package names and versions from public registries to api.deps.dev")
	cmd.Flags().Float64Var(&minScorecard, "min-scorecard", 0, "report packages whose source repository has an OpenSSF Scorecard below this score (0 to 10) as medium findings; sends package names and versions from public registries to api.deps.dev (npm, PyPI, Cargo, Go, NuGet, RubyGems)")
	cmd.Flags().BoolVar(&prioritize, "prioritize", false, "raise the severity of vulnerabilities that CISA lists as exploited (KEV) or whose EPSS score is 50% or more; sends the CVE IDs of public advisories to api.osv.dev, www.cisa.gov and api.first.org")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity: critical, high, medium, low, or info")
	return cmd
}

// parseAge reads --min-release-age, falling back to the policy's cooldown when the flag is
// not given.
func parseAge(flag, fromPolicy string) (time.Duration, error) {
	if strings.TrimSpace(flag) == "" {
		d, err := pkgpolicy.ParseAge(fromPolicy)
		if err != nil {
			return 0, fmt.Errorf("policy health min_release_age %w", err)
		}
		return d, nil
	}
	d, err := pkgpolicy.ParseAge(flag)
	if err != nil {
		return 0, fmt.Errorf("--min-release-age %w", err)
	}
	return d, nil
}

// exploitSignals looks up exploitation data for the advisories found in the scan. Only
// artifacts whose vulnerabilities were actually checked have advisories, so in public-only
// mode nothing about a private package is sent. It returns the reason when the lookup
// cannot be made, rather than an empty result that would read as "not exploited".
func exploitSignals(ctx context.Context, mode pkgpolicy.Mode, doc lockfile.Document) (map[string]exploit.Signal, string) {
	if mode == pkgpolicy.ModeOffline {
		return nil, "the lookup needs the network, and the network mode is offline"
	}
	var ids []string
	for _, art := range doc.Artifacts {
		if art.Evidence.Vulnerabilities.State != lockfile.VulnChecked {
			continue
		}
		for _, v := range art.Evidence.Vulnerabilities.Items {
			ids = append(ids, v.ID)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return nil, ""
	}
	signals, err := exploit.New().ForAdvisories(ctx, osv.New(), ids)
	if err != nil {
		return nil, err.Error()
	}
	return signals, ""
}
