package cli

import (
	"fmt"
	"github.com/securock/securock/internal/dast"
	"github.com/securock/securock/internal/finding"
	"github.com/spf13/cobra"
	"os"
)

func newAuthorizationCommand(opts *options) *cobra.Command {
	return &cobra.Command{Use: "dast-auth URL MATRIX.json", Short: "Test explicit API object and role authorization contracts", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, a []string) error {
		if opts.offline || opts.network != "allow-all" {
			return opErr(fmt.Errorf("authorization DAST requires --network allow-all"))
		}
		f, e := os.Open(a[1])
		if e != nil {
			return opErr(e)
		}
		defer f.Close()
		m, e := dast.ReadMatrix(f)
		if e != nil {
			return opErr(e)
		}
		r, scanErr := dast.Authorization(c.Context(), a[0], m, os.Getenv, nil)
		if e = finding.Write(c.OutOrStdout(), r, opts.format); e != nil {
			return opErr(e)
		}
		if scanErr != nil {
			return opErr(scanErr)
		}
		if !opts.noFail && r.AtLeast(finding.SeverityHigh) > 0 {
			return trustErr("authorization contract violated")
		}
		return nil
	}}
}
