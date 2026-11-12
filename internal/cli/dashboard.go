package cli

import (
	"github.com/securock/securock/internal/dashboard"
	"github.com/securock/securock/internal/lifecycle"
	"github.com/securock/securock/internal/runrecord"
	"github.com/spf13/cobra"
	"os"
)

func newDashboardCommand(opts *options) *cobra.Command {
	var files []string
	var asOf string
	c := &cobra.Command{Use: "dashboard ISSUES.json", Short: "Render a self-contained interactive security work queue", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		f, e := os.Open(a[0])
		if e != nil {
			return opErr(e)
		}
		defer f.Close()
		registry, e := lifecycle.Read(f)
		if e != nil {
			return opErr(e)
		}
		runs := []runrecord.Record{}
		for _, file := range files {
			r, e := readRecord(file)
			if e != nil {
				return opErr(e)
			}
			runs = append(runs, r)
		}
		return opErr(dashboard.Render(c.OutOrStdout(), registry, runs, asOf))
	}}
	c.Flags().StringArrayVar(&files, "run", nil, "scan record for trend comparison, supplied in chronological order")
	c.Flags().StringVar(&asOf, "as-of", "", "explicit overdue evaluation date YYYY-MM-DD")
	return c
}
