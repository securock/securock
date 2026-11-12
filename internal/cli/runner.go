package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/runrecord"
	"github.com/spf13/cobra"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"
)

func newRunnerCommand(opts *options) *cobra.Command {
	var origin, env string
	var once, local bool
	c := &cobra.Command{Use: "runner PROJECTS.json", Short: "Run leased offline scans against operator-mapped local projects", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if opts.offline || opts.network != "allow-all" {
			return opErr(fmt.Errorf("runner requires --network allow-all"))
		}
		u, e := url.Parse(origin)
		if e != nil {
			return opErr(e)
		}
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "https" && (!local || ip == nil || !ip.IsLoopback()) {
			return opErr(fmt.Errorf("HTTPS required except explicit loopback development"))
		}
		raw, e := os.ReadFile(a[0])
		if e != nil {
			return opErr(e)
		}
		projects := map[string]string{}
		if json.Unmarshal(raw, &projects) != nil || len(projects) == 0 {
			return opErr(fmt.Errorf("project map required"))
		}
		ids := []string{}
		for id, path := range projects {
			real, e := filepath.EvalSymlinks(path)
			if e != nil {
				return opErr(e)
			}
			info, e := os.Stat(real)
			if e != nil || !info.IsDir() {
				return opErr(fmt.Errorf("project directory required"))
			}
			projects[id] = real
			ids = append(ids, id)
		}
		slices.Sort(ids)
		exe, e := os.Executable()
		if e != nil {
			return opErr(e)
		}
		client := control.Client{URL: origin, Token: os.Getenv(env)}
		for {
			var job control.Job
			if e := client.Call(c.Context(), "POST", "/api/v1/runner/claim", map[string]any{"projects": ids}, &job); e != nil {
				return opErr(e)
			}
			if job.ID != "" {
				temp, e := os.MkdirTemp("", "securock-run-*")
				if e != nil {
					return opErr(e)
				}
				recordFile := filepath.Join(temp, "record.json")
				raw, scanErr := external.Run(c.Context(), exe, "security", projects[job.Project], "--offline", "--no-fail", "--format", "json", "--record", recordFile, "--scope-id", job.Project)
				var record *runrecord.Record
				if scanErr == nil {
					fd, e := os.Open(recordFile)
					if e != nil {
						scanErr = e
					} else {
						v, e := runrecord.Read(fd)
						fd.Close()
						if e != nil {
							scanErr = e
						} else {
							record = &v
						}
					}
				}
				_ = os.RemoveAll(temp)
				var report finding.Report
				if scanErr == nil {
					scanErr = json.Unmarshal(raw, &report)
				}
				var result control.Job
				if e := client.Call(c.Context(), "POST", "/api/v1/runner/complete", map[string]any{"id": job.ID, "lease": job.Lease, "report": report, "failed": scanErr != nil, "record": record}, &result); e != nil {
					return opErr(e)
				}
				fmt.Fprintf(c.OutOrStdout(), "job %s %s\n", job.ID, result.Status)
			}
			if once {
				return nil
			}
			select {
			case <-c.Context().Done():
				return nil
			case <-time.After(5 * time.Second):
			}
		}
	}}
	c.Flags().StringVar(&origin, "server", "", "control plane origin")
	c.Flags().StringVar(&env, "token-env", "SECUROCK_TOKEN", "runner OIDC token environment variable")
	c.Flags().BoolVar(&once, "once", false, "claim and process at most one job")
	c.Flags().BoolVar(&local, "local-http", false, "permit literal-loopback HTTP development")
	return c
}
