package cli

import (
	"bytes"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/monitor"
	"github.com/securock/securock/internal/policy"
	p "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func newWatchCommand(opts *options) *cobra.Command {
	var interval time.Duration
	var runs int
	var state, webhookEnv, fail string
	c := &cobra.Command{Use: "watch [path] -- [security flags]", Short: "Periodically scan, compare findings, and notify a configured HTTPS webhook", Args: cobra.ArbitraryArgs, RunE: func(c *cobra.Command, a []string) error {
		if interval < time.Second || runs < 0 {
			return opErr(fmt.Errorf("interval must be at least 1s and runs nonnegative"))
		}
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
		endpoint := ""
		if webhookEnv != "" {
			if net.ResolvedMode() != p.ModeAllowAll {
				return opErr(fmt.Errorf("webhook delivery requires --network allow-all"))
			}
			endpoint = os.Getenv(webhookEnv)
			if endpoint == "" {
				return opErr(fmt.Errorf("webhook environment variable is empty"))
			}
		}
		dash := c.ArgsLenAtDash()
		var extra []string
		if dash >= 0 {
			extra = a[dash:]
			a = a[:dash]
		}
		if len(a) > 1 {
			return opErr(fmt.Errorf("watch accepts one project path"))
		}
		project := projectPath(a)
		for iteration := 0; runs == 0 || iteration < runs; iteration++ {
			old := finding.New("security", nil)
			if f, e := os.Open(state); e == nil {
				old, e = baseline.Read(f)
				f.Close()
				if e != nil {
					return opErr(e)
				}
			} else if !os.IsNotExist(e) {
				return opErr(e)
			}
			args := append([]string{"security", project}, extra...)
			if opts.offline {
				args = append(args, "--offline")
			}
			if opts.network != "" {
				args = append(args, "--network", opts.network)
			}
			if opts.policy != "" {
				args = append(args, "--policy", opts.policy)
			}
			if opts.profile != "" {
				args = append(args, "--profile", opts.profile)
			}
			args = append(args, "--format", "json", "--no-fail")
			root := NewRoot("watch", "none", "unknown")
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(c.ErrOrStderr())
			root.SetContext(c.Context())
			root.SetArgs(args)
			scanErr := root.Execute()
			current, e := baseline.Read(bytes.NewReader(out.Bytes()))
			if e != nil {
				return opErr(fmt.Errorf("scan did not produce a valid finding report"))
			}
			changed := baseline.New(old, current)
			if e := finding.Write(c.OutOrStdout(), changed, opts.format); e != nil {
				return opErr(e)
			}
			if scanErr != nil {
				return opErr(scanErr)
			}
			complete := true
			for _, f := range current.Findings {
				if baseline.Incomplete(f) {
					complete = false
				}
			}
			if changed.AtLeast(sev) > 0 && endpoint != "" {
				var alerts []finding.Finding
				for _, f := range changed.Findings {
					if f.Suppressed == nil && f.Severity.Rank() >= sev.Rank() {
						alerts = append(alerts, f)
					}
				}
				if e := monitor.Notify(c.Context(), endpoint, finding.New("security", alerts)); e != nil {
					return opErr(e)
				}
			}
			if e := monitor.Save(state, monitor.Merge(old, current)); e != nil {
				return opErr(e)
			}
			if !complete {
				fmt.Fprintln(c.ErrOrStderr(), "Coverage is incomplete; previously observed risks remain in the baseline.")
			}

			if runs > 0 && iteration+1 >= runs {
				break
			}
			timer := time.NewTimer(interval)
			select {
			case <-c.Context().Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		return nil
	}}
	c.Flags().DurationVar(&interval, "interval", time.Hour, "delay between scans")
	c.Flags().IntVar(&runs, "runs", 0, "number of runs; 0 continues until cancelled")
	c.Flags().StringVar(&state, "state", ".securock-monitor.json", "private report baseline file")
	c.Flags().StringVar(&webhookEnv, "webhook-env", "", "environment variable containing a notification HTTPS URL")
	c.Flags().StringVar(&fail, "fail-on", "high", "minimum severity to notify")
	return c
}
