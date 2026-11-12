package cli

import (
	"fmt"
	"github.com/securock/securock/internal/dast"
	"github.com/securock/securock/internal/finding"
	"github.com/spf13/cobra"
	"os"
)

func newScenarioCommand(opts *options) *cobra.Command {
	var mutations bool
	c := &cobra.Command{Use: "dast-scenario URL SCENARIO.json", Short: "Run explicit authenticated HTTP workflows with in-memory cookies and captures", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, a []string) error {
		if opts.offline || opts.network != "allow-all" {
			return opErr(fmt.Errorf("scenario DAST requires --network allow-all"))
		}
		f, e := os.Open(a[1])
		if e != nil {
			return opErr(e)
		}
		s, e := dast.ReadScenario(f)
		f.Close()
		if e != nil {
			return opErr(e)
		}
		r, scanErr := dast.RunScenario(c.Context(), a[0], s, mutations, os.Getenv, nil)
		if e = finding.Write(c.OutOrStdout(), r, opts.format); e != nil {
			return opErr(e)
		}
		if scanErr != nil {
			return opErr(scanErr)
		}
		if !opts.noFail && r.AtLeast(finding.SeverityHigh) > 0 {
			return trustErr("scenario contract violated")
		}
		return nil
	}}
	c.Flags().BoolVar(&mutations, "allow-mutations", false, "explicitly permit the non-GET/HEAD operations listed in this test scenario")
	return c
}
