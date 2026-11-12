package cli

import (
	"bytes"
	"fmt"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/policy"
	p "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
	"time"
)

func scanImage(cmd *cobra.Command, image string, archive bool, net p.Network) (finding.Report, error) {
	if net.ResolvedMode() != p.ModeOffline && net.ResolvedMode() != p.ModeAllowAll {
		return finding.New("container", nil), fmt.Errorf("container database access requires --network allow-all, or use --offline with a local archive")
	}
	args := []string{"image", "--format", "sarif", "--scanners", "vuln,secret", "--exit-code", "0"}
	if archive {
		args = append(args, "--input", image)
	} else {
		if net.ResolvedMode() != p.ModeAllowAll {
			return finding.New("container", nil), fmt.Errorf("image registry access requires --network allow-all; use --archive for offline input")
		}
		args = append(args, "--", image)
	}
	if net.ResolvedMode() == p.ModeOffline {
		args = append([]string{"image", "--offline-scan", "--skip-db-update", "--skip-java-db-update"}, args[1:]...)
	}
	raw, e := external.Run(cmd.Context(), "trivy", args...)
	if e != nil {
		return finding.New("container", []finding.Finding{{ID: "container:analysis-incomplete", Severity: finding.SeverityHigh, Subject: image, Title: "Container scan did not complete", Remediation: "Install Trivy and its vulnerability database, then retry."}}), e
	}
	found, e := finding.ReadSARIF(bytes.NewReader(raw))
	if e != nil {
		found = append(found, finding.Finding{ID: "container:analysis-incomplete", Severity: finding.SeverityHigh, Title: "Trivy did not produce valid SARIF", Subject: image})
	}
	return finding.New("container", found), e
}
func newContainerCommand(opts *options) *cobra.Command {
	var archive bool
	var fail string
	c := &cobra.Command{Use: "container IMAGE", Short: "Scan image packages and secrets using installed Trivy", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		sev, e := finding.ParseSeverity(fail)
		if e != nil {
			return opErr(e)
		}
		pol, e := policy.LoadWithProfile(opts.policy, opts.profile)
		if e != nil {
			return opErr(e)
		}
		net, e := scanOptions(opts, pol)
		if e != nil {
			return e
		}
		accepted, e := exceptions.Load(exceptions.Path(".", opts.exceptions))
		if e != nil {
			return opErr(e)
		}
		r, scanErr := scanImage(c, a[0], archive, net)
		r = exceptions.Apply(r, accepted, time.Now().UTC())
		if e := finding.Write(c.OutOrStdout(), r, opts.format); e != nil {
			return opErr(e)
		}
		if scanErr != nil {
			return opErr(scanErr)
		}
		if !opts.noFail && r.AtLeast(sev) > 0 {
			return trustErr("container findings at or above %s", sev)
		}
		return nil
	}}
	c.Flags().BoolVar(&archive, "archive", false, "treat IMAGE as a local image archive")
	c.Flags().StringVar(&fail, "fail-on", "high", "severity threshold")
	return c
}
