package cli

import (
	"fmt"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/history"
	"github.com/spf13/cobra"
	"time"
)

func newHistoryCommand(opts *options) *cobra.Command {
	var rev, fail string
	var all bool
	var commits, blobs int
	c := &cobra.Command{Use: "history [path]", Short: "Find credential patterns in reachable historical Git blobs", Args: cobra.MaximumNArgs(1), RunE: func(c *cobra.Command, a []string) error {
		sev, e := finding.ParseSeverity(fail)
		if e != nil {
			return opErr(e)
		}
		path := projectPath(a)
		accepted, e := exceptions.Load(exceptions.Path(path, opts.exceptions))
		if e != nil {
			return opErr(e)
		}
		r, scanErr := history.Scan(c.Context(), history.Options{Path: path, Revision: rev, AllRefs: all, MaxCommits: commits, MaxBlobs: blobs})
		r = exceptions.Apply(r, accepted, time.Now().UTC())
		if e := finding.Write(c.OutOrStdout(), r, opts.format); e != nil {
			return opErr(e)
		}
		if scanErr != nil {
			return opErr(scanErr)
		}
		if !opts.noFail && r.AtLeast(sev) > 0 {
			return trustErr("history credential findings at or above %s", sev)
		}
		return nil
	}}
	c.Flags().StringVar(&rev, "revision", "HEAD", "reachable commit tip")
	c.Flags().BoolVar(&all, "all-refs", false, "scan commits reachable from all local refs")
	c.Flags().IntVar(&commits, "max-commits", 1000, "commit budget; exhaustion fails closed")
	c.Flags().IntVar(&blobs, "max-blobs", 10000, "unique blob budget; exhaustion fails closed")
	c.Flags().StringVar(&fail, "fail-on", "high", "severity threshold")
	c.Long = fmt.Sprint("Inspect reachable Git blobs in memory. No checkout, remote fetch, credential validation, or history rewrite is performed. Values are never printed. Unreachable objects, reflogs and LFS payloads are outside this scan.")
	return c
}
