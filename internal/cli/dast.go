package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/securock/securock/internal/dynamic"
	"github.com/securock/securock/internal/external"
	"os"
	"strings"
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
	var bearerEnv, openapi string
	var browser bool
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
			openapiSkipped := 0
			token := ""
			if bearerEnv != "" {
				token = os.Getenv(bearerEnv)
				if token == "" || strings.ContainsAny(token, "\r\n") {
					return opErr(fmt.Errorf("bearer environment variable is missing or invalid"))
				}
			}
			if openapi != "" {
				if len(args) != 1 {
					return opErr(fmt.Errorf("OpenAPI requires one target origin"))
				}
				f, e := os.Open(openapi)
				if e != nil {
					return opErr(e)
				}
				urls, skipped, e := dynamic.Endpoints(f, args[0])
				f.Close()
				if e != nil {
					return opErr(e)
				}
				args = append(args, urls...)
				openapiSkipped = skipped
				if skipped > 0 {
					fmt.Fprintln(cmd.ErrOrStderr(), "OpenAPI parameterized or out-of-scope paths skipped:", skipped)
				}
			}
			var found []finding.Finding
			if openapiSkipped > 0 {
				found = append(found, finding.Finding{ID: "dast:openapi-incomplete", Severity: finding.SeverityInfo, Title: "OpenAPI paths could not be expanded", Detail: "Parameterized or out-of-scope GET paths require explicit concrete targets."})
			}
			var scanErr error
			for _, target := range args {
				r, e := dast.Scan(cmd.Context(), dast.Options{URL: target, Timeout: timeout, BearerToken: token})
				found = append(found, r.Findings...)
				scanErr = errors.Join(scanErr, e)
				if browser {
					raw, e := external.Run(cmd.Context(), "node", "-e", dynamic.BrowserScript, target, bearerEnv)
					if e == nil {
						var r finding.Report
						e = json.NewDecoder(bytes.NewReader(raw)).Decode(&r)
						if e == nil {
							found = append(found, r.Findings...)
						}
					}
					if e != nil {
						found = append(found, finding.Finding{ID: "dast:browser-incomplete", Severity: finding.SeverityHigh, Title: "Browser analysis failed", Subject: target})
						scanErr = errors.Join(scanErr, e)
					}
				}
			}
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
	cmd.Flags().StringVar(&bearerEnv, "bearer-env", "", "read a bearer token from an environment variable")
	cmd.Flags().StringVar(&openapi, "openapi", "", "read static GET endpoints from OpenAPI 3 JSON")
	cmd.Flags().BoolVar(&browser, "browser", false, "also inspect the rendered DOM using installed Node.js and Playwright")
	return cmd
}
