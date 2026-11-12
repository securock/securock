package cli

import (
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/remediation"
	"github.com/securock/securock/internal/sast"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func newRemediateCommand(opts *options) *cobra.Command {
	var project, patchdir string
	var verify bool
	c := &cobra.Command{Use: "remediate REPORT.json", Short: "Build a remediation plan and optional reviewable patches", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		r, e := readFindingReport(a[0])
		if e != nil {
			return opErr(e)
		}
		if verify {
			found, e := sast.Analyze(project)
			if e != nil {
				return opErr(e)
			}
			current := finding.New("sast", found)
			var old []finding.Finding
			for _, f := range r.Findings {
				if len(f.ID) >= 5 && f.ID[:5] == "sast:" {
					old = append(old, f)
				}
			}
			newReport := baseline.New(finding.New("sast", old), current)
			if e := finding.Write(c.OutOrStdout(), current, opts.format); e != nil {
				return opErr(e)
			}
			if !opts.noFail && newReport.AtLeast(finding.SeverityHigh) > 0 {
				return trustErr("new high source findings after remediation")
			}
			return nil
		}
		if patchdir != "" {
			if e := os.MkdirAll(patchdir, 0700); e != nil {
				return opErr(e)
			}
		}
		for i, f := range r.Findings {
			if f.Suppressed != nil {
				continue
			}
			fmt.Fprintf(c.OutOrStdout(), "[%s] %s %s\n%s\n\n", f.Severity, f.ID, f.Subject, f.Remediation)
			if patchdir != "" {
				patch, e := remediation.Patch(project, f)
				if e != nil {
					return opErr(e)
				}
				if patch != "" {
					name := filepath.Join(patchdir, fmt.Sprintf("fix-%04d.patch", i))
					fd, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if e != nil {
						return opErr(e)
					}
					_, e = fd.WriteString(patch)
					fd.Close()
					if e != nil {
						return opErr(e)
					}
				}
			}
		}
		return nil
	}}
	c.Flags().StringVar(&project, "project", ".", "project root")
	c.Flags().StringVar(&patchdir, "patch-dir", "", "write reviewable TLS verification patches without applying them")
	c.Flags().BoolVar(&verify, "verify", false, "rerun offline source analysis and fail on new high source findings")
	return c
}
