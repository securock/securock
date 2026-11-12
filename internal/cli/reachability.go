package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
	"github.com/spf13/cobra"
)

func newCallReachabilityCommand(opts *options) *cobra.Command {
	var project string
	var entries []string
	c := &cobra.Command{Use: "reachability SYMBOLS.json", Short: "Trace potential Go calls from explicit entrypoints to advisory symbols offline", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if len(entries) == 0 || len(entries) > 100 {
			return opErr(fmt.Errorf("provide 1-100 fully qualified --entry functions"))
		}
		f, e := os.Open(a[0])
		if e != nil {
			return opErr(e)
		}
		raw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
		f.Close()
		if e != nil || len(raw) > 1<<20 {
			return opErr(fmt.Errorf("symbol manifest exceeds limit"))
		}
		var manifest struct {
			Version int           `json:"version"`
			Symbols []sast.Symbol `json:"symbols"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF || manifest.Version != 1 || len(manifest.Symbols) == 0 || len(manifest.Symbols) > 1000 {
			return opErr(fmt.Errorf("invalid version 1 symbol manifest"))
		}
		seen := map[string]bool{}
		for _, s := range manifest.Symbols {
			key := s.ID + "\x00" + s.Name
			if s.ID == "" || s.Name == "" || seen[key] {
				return opErr(fmt.Errorf("symbol manifest requires unique advisory/symbol pairs"))
			}
			seen[key] = true
		}
		report, e := sast.Calls(project, entries, manifest.Symbols)
		if e != nil {
			return opErr(e)
		}
		if e = finding.Write(c.OutOrStdout(), report, opts.format); e != nil {
			return opErr(e)
		}
		for _, f := range report.Findings {
			if f.ID == "reachability:entry-unavailable" || f.ID == "sast:analysis-incomplete" {
				return opErr(fmt.Errorf("call analysis incomplete"))
			}
		}
		return nil
	}}
	c.Flags().StringVar(&project, "project", ".", "Go project root")
	c.Flags().StringArrayVar(&entries, "entry", nil, "fully qualified entry function, repeatable (for example example.org/app.main)")
	return c
}
