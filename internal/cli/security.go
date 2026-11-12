package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/coverage"
	"github.com/securock/securock/internal/dast"
	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/organization"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/runrecord"
	"github.com/securock/securock/internal/sast"
	"github.com/securock/securock/internal/scanner"
	pkgpolicy "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
)

func newSecurityCommand(opts *options) *cobra.Command {
	var failOn string
	var assumeParams bool
	var imports []string
	var targets []string
	var dastTimeout time.Duration
	var inventories []string
	var awsRegion, awsProfile string
	var coverageOutput string
	var recordPath, scopeID string
	var orgFile, serviceID, orgDate string
	var scopes cloudScopes
	cmd := &cobra.Command{
		Use:   "security [path]",
		Short: "Audit dependencies, source code, secrets, and infrastructure together",
		Long: `Run dependency auditing and offline source, secret, and infrastructure analysis
in one severity-ranked report. Dependency checks use the supported lockfiles in
the project directory; no securock.lock is required or written. If none is found,
the report explicitly marks dependency analysis as unchecked. Use --import to
include other scanners' SARIF results, or --target for opt-in live HTTP checks
(requires allow-all network mode). Exceptions and --fail-on apply to the
combined report. Operational failures still exit 2, even with --no-fail.`,
		Args: cobra.MaximumNArgs(1),
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
			if err := validateDAST(targets, dastTimeout, net); err != nil {
				return opErr(err)
			}
			if err := validateCSPM(awsRegion, awsProfile, net); err != nil {
				return opErr(err)
			}
			if err := scopes.validate(net); err != nil {
				return opErr(err)
			}
			var orgPolicy organization.Policy
			if orgFile != "" {
				orgPolicy, err = loadOrganization(orgFile)
				if err != nil {
					return opErr(err)
				}
				if _, err := organization.Evaluate(finding.New("security", nil), orgPolicy, serviceID, orgDate); err != nil {
					return opErr(err)
				}
				minimum, _ := finding.ParseSeverity(orgPolicy.Services[serviceID].FailOn)
				if minimum.Rank() < threshold.Rank() {
					threshold = minimum
				}
			} else if serviceID != "" || orgDate != "" {
				return opErr(fmt.Errorf("service and policy-date require org-policy"))
			}
			cooldown, err := parseAge("", pol.Rules.Health.MinReleaseAge)
			if err != nil {
				return opErr(err)
			}
			path := projectPath(args)
			accepted, err := exceptions.Load(exceptions.Path(path, opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			found, err := sast.AnalyzeWith(path, sast.Options{AssumeParams: assumeParams})
			if err != nil {
				return opErr(err)
			}
			external, err := importedFindings(cmd, path, imports)
			if err != nil {
				return opErr(err)
			}
			found = append(found, external...)
			var scanErr error
			if len(ecosystem.Detect(path)) == 0 {
				found = append(found, finding.Finding{
					ID: "security:dependencies-unchecked", Severity: finding.SeverityInfo,
					Title: "Dependencies were not checked", Detail: "No supported lockfile found in the project directory.",
					Remediation: "Generate a supported package-manager lockfile, or run security in each dependency project directory.",
				})
			} else {
				result, err := scanner.Scan(cmd.Context(), scanner.Options{
					Path: path, Offline: opts.offline, Network: net, Policy: pol, Reachability: opts.reachability,
				})
				if err != nil {
					// Preserve source findings when a registry or dependency parser fails.
					scanErr = fmt.Errorf("dependency analysis incomplete: %w", err)
					found = append(found, finding.Finding{
						ID: "security:dependencies-incomplete", Severity: finding.SeverityHigh,
						Title:       "Dependency analysis could not complete",
						Remediation: "Fix the dependency lockfile or registry access and rerun security; see the command error for details.",
					})
				} else {
					dependencies := audit.RunWith(result.Document, audit.Options{
						MinReleaseAge: cooldown, InternalNames: pol.Rules.Health.InternalNames,
					})
					location := reportLocation(path, opts.lockPath)
					if abs, err := filepath.Abs(location); err == nil {
						location = filepath.ToSlash(abs)
					}
					// Source findings keep their own locations; dependency findings anchor
					// to the lockfile without assigning that location to the whole report.
					for _, f := range dependencies.Findings {
						f.Location = &finding.Location{File: location, Line: 1}
						found = append(found, f)
					}
				}
			}
			live, liveErr := scanDAST(cmd.Context(), targets, dastTimeout)
			found = append(found, live...)
			scanErr = errors.Join(scanErr, liveErr)
			cloud, cloudErr := scanCSPM(cmd.Context(), inventories, awsRegion, awsProfile)
			found = append(found, cloud...)
			scanErr = errors.Join(scanErr, cloudErr)
			extra, extraErr := scopes.scan(cmd.Context())
			found = append(found, extra...)
			scanErr = errors.Join(scanErr, extraErr)
			if abs, err := filepath.Abs(path); err == nil {
				finding.RelativeTo(found, abs)
			}
			report := exceptions.Apply(finding.New("security", found), accepted, time.Now().UTC())
			if orgFile != "" {
				governed, e := organization.Evaluate(report, orgPolicy, serviceID, orgDate)
				if e != nil {
					return opErr(e)
				}
				report = governed.Report
			}
			if recordPath != "" {
				digest, e := pkgpolicy.Fingerprint(pol)
				if e != nil {
					return opErr(e)
				}
				if orgFile != "" {
					digest = runrecord.Digest([]string{digest, runrecord.Digest(orgPolicy)})
				}
				if e := writeRunRecord(cmd, opts, path, recordPath, scopeID, report, scanErr == nil, digest); e != nil {
					return opErr(e)
				}
			}
			if coverageOutput != "" {
				raw, err := json.MarshalIndent(coverage.Build(report, targets, inventories, awsRegion), "", "  ")
				if err != nil {
					return opErr(err)
				}
				if err := os.WriteFile(coverageOutput, append(raw, '\n'), 0600); err != nil {
					return opErr(err)
				}
			}
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
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when an unaccepted finding meets this severity: critical, high, medium, low, or info")
	cmd.Flags().StringArrayVar(&imports, "import", nil, "include a SARIF 2.1.0 report from another scanner (repeatable; - reads stdin)")
	cmd.Flags().BoolVar(&assumeParams, "assume-params", false, "treat string parameters of otherwise uncalled Go functions as untrusted")
	cmd.Flags().StringArrayVar(&targets, "target", nil, "also inspect this live HTTP application URL (repeatable; requires --network allow-all)")
	cmd.Flags().DurationVar(&dastTimeout, "dast-timeout", dast.DefaultTimeout, "total DAST request timeout per target, including redirects")
	cmd.Flags().StringArrayVar(&inventories, "cloud-inventory", nil, "also inspect an AWS Config inventory JSON file (repeatable; works offline)")
	cmd.Flags().StringVar(&awsRegion, "aws-region", "", "collect recorded AWS Config resources through the AWS CLI in this region (requires allow-all)")
	cmd.Flags().StringVar(&awsProfile, "aws-profile", "", "AWS CLI profile for --aws-region")
	cmd.Flags().StringVar(&coverageOutput, "coverage-output", "", "write a JSON scope and incomplete-evidence summary")
	cmd.Flags().StringVar(&recordPath, "record", "", "write an integrity-checked scan record")
	cmd.Flags().StringVar(&scopeID, "scope-id", "", "stable project identity for comparable scan records")
	cmd.Flags().StringVar(&orgFile, "org-policy", "", "organization policy overlay")
	cmd.Flags().StringVar(&serviceID, "service", "", "service identity in organization policy")
	cmd.Flags().StringVar(&orgDate, "policy-date", "", "explicit organization policy evaluation date YYYY-MM-DD")
	scopes.bind(cmd)
	return cmd
}
