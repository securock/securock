package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/prioritization"
	"github.com/spf13/cobra"
	"os"
)

func newPrioritizeCommand(opts *options) *cobra.Command {
	var assets string
	c := &cobra.Command{Use: "prioritize REPORT.json", Short: "Rank findings with explicit asset exposure and business context", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		r, e := readFindingReport(a[0])
		if e != nil {
			return opErr(e)
		}
		ctx := prioritization.Context{Version: 1}
		if assets != "" {
			f, e := os.Open(assets)
			if e != nil {
				return opErr(e)
			}
			ctx, e = prioritization.Read(f)
			f.Close()
			if e != nil {
				return opErr(e)
			}
		}
		ranked := prioritization.Rank(r, ctx)
		if opts.format == "json" {
			return json.NewEncoder(c.OutOrStdout()).Encode(ranked)
		}
		if opts.format != "text" {
			return opErr(fmt.Errorf("prioritize supports text or json"))
		}
		fmt.Fprintln(c.OutOrStdout(), ranked.Limitation)
		for _, item := range ranked.Items {
			fmt.Fprintf(c.OutOrStdout(), "%d [%s] %s %s owner=%s\n", item.Score, item.Finding.Severity, item.Finding.ID, item.Finding.Subject, item.Owner)
		}
		return nil
	}}
	c.Flags().StringVar(&assets, "assets", "", "version 1 asset context JSON with evidence references")
	return c
}
