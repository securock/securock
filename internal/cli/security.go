package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/securock/securock/internal/audit"
	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/sast"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newSecurityCommand(opts *options) *cobra.Command {
	var failOn string
	var assumeParams bool
	var imports []string
	cmd := &cobra.Command{
		Use:   "security [path]",
		Short: "Audit dependencies, source code, secrets, and infrastructure together",
		Long: `Run dependency auditing and offline source, secret, and infrastructure analysis
in one severity-ranked report. Dependency checks use the supported lockfiles in
the project directory; no securock.lock is required or written. If none is found,
the report explicitly marks dependency analysis as unchecked. Use --import to
include other scanners' SARIF results. Exceptions and --fail-on apply to the
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
			if abs, err := filepath.Abs(path); err == nil {
				finding.RelativeTo(found, abs)
			}
			report := exceptions.Apply(finding.New("security", found), accepted, time.Now().UTC())
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
	return cmd
}
