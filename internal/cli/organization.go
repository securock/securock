package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/organization"
	"github.com/spf13/cobra"
	"os"
)

func loadOrganization(file string) (organization.Policy, error) {
	f, e := os.Open(file)
	if e != nil {
		return organization.Policy{}, e
	}
	defer f.Close()
	return organization.Read(f)
}
func newEnforceCommand(opts *options) *cobra.Command {
	var file, service, asOf string
	c := &cobra.Command{Use: "enforce REPORT.json", Short: "Apply service ownership SLA and reviewed-exception rules", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		r, e := readFindingReport(a[0])
		if e != nil {
			return opErr(e)
		}
		p, e := loadOrganization(file)
		if e != nil {
			return opErr(e)
		}
		result, e := organization.Evaluate(r, p, service, asOf)
		if e != nil {
			return opErr(e)
		}
		if opts.format == "json" {
			if e := json.NewEncoder(c.OutOrStdout()).Encode(result); e != nil {
				return opErr(e)
			}
		} else if opts.format == "text" {
			if e := finding.Write(c.OutOrStdout(), result.Report, "text"); e != nil {
				return opErr(e)
			}
			for _, task := range result.Tasks {
				fmt.Fprintf(c.OutOrStdout(), "%s owner=%s due=%s priority=%d\n", task.Key, task.Owner, task.Due, task.Priority)
			}
		} else {
			return opErr(fmt.Errorf("enforce supports text or json"))
		}
		sev, _ := finding.ParseSeverity(p.Services[service].FailOn)
		if !opts.noFail && result.Report.AtLeast(sev) > 0 {
			return trustErr("organization gate failed")
		}
		return nil
	}}
	c.Flags().StringVar(&file, "organization", "", "organization policy JSON")
	c.Flags().StringVar(&service, "service", "", "service identity")
	c.Flags().StringVar(&asOf, "as-of", "", "explicit evaluation date YYYY-MM-DD")
	return c
}
