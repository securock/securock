package cli

import (
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/protect"
	"github.com/spf13/cobra"
	"net"
	"net/url"
	"os"
	"time"
)

func newProtectCommand(opts *options) *cobra.Command {
	var receive bool
	var server, env string
	c := &cobra.Command{Use: "protect [PROJECT]", Short: "Block staged or received commits containing credential patterns", Args: cobra.MaximumNArgs(1), RunE: func(c *cobra.Command, a []string) error {
		approvals := map[string]control.Approval{}
		if server != "" {
			if opts.offline || opts.network != "allow-all" {
				return opErr(fmt.Errorf("online approvals require --network allow-all"))
			}
			u, e := url.Parse(server)
			if e != nil {
				return opErr(e)
			}
			ip := net.ParseIP(u.Hostname())
			if u.Scheme != "https" && (ip == nil || !ip.IsLoopback()) {
				return opErr(fmt.Errorf("approval service requires HTTPS"))
			}
			client := control.Client{URL: server, Token: os.Getenv(env)}
			if e = client.Call(c.Context(), "GET", "/api/v1/approvals", nil, &approvals); e != nil {
				return opErr(e)
			}
		}
		var r finding.Report
		var e error
		if receive {
			r, e = protect.Receive(c.Context(), projectPath(a), c.InOrStdin())
		} else {
			r, e = protect.Staged(c.Context(), projectPath(a))
		}
		r = protect.Apply(r, approvals, time.Now())
		if writeErr := finding.Write(c.OutOrStdout(), r, opts.format); writeErr != nil {
			return opErr(writeErr)
		}
		if e != nil {
			return opErr(e)
		}
		if r.AtLeast(finding.SeverityHigh) > 0 {
			return trustErr("credential push protection blocked the operation")
		}
		return nil
	}}
	c.Flags().BoolVar(&receive, "pre-receive", false, "read old/new/ref commands from stdin and scan received reachable text history")
	c.Flags().StringVar(&server, "server", "", "optional authenticated exception authority origin")
	c.Flags().StringVar(&env, "token-env", "SECUROCK_TOKEN", "OIDC token for reading exact approved exceptions")
	return c
}
