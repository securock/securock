package cli

import (
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"github.com/spf13/cobra"
	"os"
)

func readFindingReport(file string) (finding.Report, error) {
	f, e := os.Open(file)
	if e != nil {
		return finding.Report{}, e
	}
	defer f.Close()
	return baseline.Read(f)
}
func newBaselineCommand(opts *options) *cobra.Command {
	var fail string
	c := &cobra.Command{Use: "baseline OLD.json CURRENT.json", Short: "Report new findings and severity changes against a saved report", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, args []string) error {
		sev, e := finding.ParseSeverity(fail)
		if e != nil {
			return opErr(e)
		}
		old, e := readFindingReport(args[0])
		if e != nil {
			return opErr(e)
		}
		current, e := readFindingReport(args[1])
		if e != nil {
			return opErr(e)
		}
		if old.Tool != current.Tool {
			return opErr(fmt.Errorf("baseline report tools must match"))
		}
		report := baseline.New(old, current)
		if e := finding.Write(c.OutOrStdout(), report, opts.format); e != nil {
			return opErr(e)
		}
		if !opts.noFail && report.AtLeast(sev) > 0 {
			return trustErr("new findings at or above %s", sev)
		}
		return nil
	}}
	c.Flags().StringVar(&fail, "fail-on", "high", "severity threshold for new findings")
	return c
}
