package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/securock/securock/internal/cspm"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/policy"
	pkgpolicy "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
)

func validateCSPM(region, profile string, net pkgpolicy.Network) error {
	if profile != "" && region == "" {
		return fmt.Errorf("--aws-profile requires --aws-region")
	}
	if region != "" {
		if net.ResolvedMode() != pkgpolicy.ModeAllowAll {
			return fmt.Errorf("live CSPM collection requires --network allow-all; use an exported inventory for offline checks")
		}
		if _, err := cspm.AWSCommand(region, profile); err != nil {
			return err
		}
	}
	return nil
}

func scanCSPM(ctx context.Context, files []string, region, profile string) ([]finding.Finding, error) {
	var found []finding.Finding
	var failures []error
	incomplete := func(detail string) {
		found = append(found, finding.Finding{ID: "cspm:analysis-incomplete", Severity: finding.SeverityHigh, Subject: "aws-config", Title: "Cloud configuration analysis did not complete", Detail: detail, Remediation: "Provide a complete AWS Config inventory or repair read-only collection and rerun CSPM."})
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			incomplete("An inventory file could not be opened.")
			failures = append(failures, fmt.Errorf("cannot open CSPM inventory"))
			continue
		}
		report, err := cspm.Read(f)
		f.Close()
		found = append(found, report.Findings...)
		if err != nil {
			incomplete(err.Error())
			failures = append(failures, err)
		}
	}
	if region != "" {
		raw, err := cspm.CollectAWS(ctx, region, profile)
		if err != nil {
			incomplete(err.Error())
			failures = append(failures, err)
		} else {
			report, err := cspm.Read(bytes.NewReader(raw))
			found = append(found, report.Findings...)
			if err != nil {
				incomplete(err.Error())
				failures = append(failures, err)
			}
		}
	}
	return found, errors.Join(failures...)
}

func newCSPMCommand(opts *options) *cobra.Command {
	var region, profile, failOn string
	cmd := &cobra.Command{
		Use: "cspm [inventory.json...]", Short: "Audit recorded AWS cloud configuration and permissions",
		Long: `Inspect AWS Config configurationItems snapshots or select-resource-config Results.
Offline inventory analysis requires no credentials or cloud tools. --aws-region
collects recorded configuration through a read-only AWS CLI query, using existing
credentials, and requires allow-all network mode. No cloud resources are changed.
Checks cover S3, EC2 security groups, RDS, IAM policies/roles, and CloudTrail.
Unavailable settings and resource types are explicit; this is not a compliance
certification or proof of effective access.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && region == "" {
				return opErr(fmt.Errorf("provide an AWS Config inventory or --aws-region for read-only collection"))
			}
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
			if err := validateCSPM(region, profile, net); err != nil {
				return opErr(err)
			}
			accepted, err := exceptions.Load(exceptions.Path(".", opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			found, scanErr := scanCSPM(cmd.Context(), args, region, profile)
			report := exceptions.Apply(finding.New("cspm", found), accepted, time.Now().UTC())
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
	cmd.Flags().StringVar(&region, "aws-region", "", "collect AWS Config recorded resources in this region using the AWS CLI (requires allow-all)")
	cmd.Flags().StringVar(&profile, "aws-profile", "", "AWS CLI profile for --aws-region; credentials are never accepted as flags")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 at this severity: critical, high, medium, low, or info")
	return cmd
}
