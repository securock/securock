package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/remediation"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func newFixPRCommand(opts *options) *cobra.Command {
	var project, branch, plan, publish, base, remote string
	c := &cobra.Command{Use: "fix-pr REPORT.json", Short: "Apply supported fixes on an isolated branch, test and rescan before optional publication", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if publish != "" && publish != "github" && publish != "gitlab" {
			return opErr(fmt.Errorf("publish must be github or gitlab"))
		}
		if publish != "" && (opts.offline || opts.network != "allow-all") {
			return opErr(fmt.Errorf("publication requires --network allow-all"))
		}
		r, e := readFindingReport(a[0])
		if e != nil {
			return opErr(e)
		}
		f, e := os.Open(plan)
		if e != nil {
			return opErr(e)
		}
		tests, e := remediation.ReadTests(f)
		f.Close()
		if e != nil {
			return opErr(e)
		}
		result, e := remediation.Fix(c.Context(), project, branch, r, tests)
		if e != nil {
			return opErr(e)
		}
		if publish != "" {
			if _, e = external.Run(c.Context(), "git", "-C", project, "push", remote, branch); e != nil {
				return opErr(e)
			}
			dir, e := os.MkdirTemp("", "securock-pr-*")
			if e != nil {
				return opErr(e)
			}
			defer os.RemoveAll(dir)
			body := filepath.Join(dir, "body.md")
			if e = os.WriteFile(body, []byte("Restore TLS certificate verification. Configured tests and source rescanning passed. Review connection trust requirements before merging.\n"), 0600); e != nil {
				return opErr(e)
			}
			tool := "gh"
			args := []string{"pr", "create", "--head", branch, "--base", base, "--title", "Restore TLS certificate verification", "--body-file", body}
			if publish == "gitlab" {
				tool = "glab"
				args = []string{"mr", "create", "--source-branch", branch, "--target-branch", base, "--title", "Restore TLS certificate verification", "--description", "Configured tests and source rescanning passed; review TLS trust before merging."}
			}
			if _, e = external.RunAt(c.Context(), project, tool, args...); e != nil {
				return opErr(e)
			}
		}
		return opErr(json.NewEncoder(c.OutOrStdout()).Encode(result))
	}}
	c.Flags().StringVar(&project, "project", ".", "clean local Git project")
	c.Flags().StringVar(&branch, "branch", "securock/tls-fix", "new remediation branch")
	c.Flags().StringVar(&plan, "tests", "", "operator-reviewed JSON test command plan")
	c.Flags().StringVar(&publish, "publish", "", "explicitly push and create a PR: github or gitlab")
	c.Flags().StringVar(&base, "base", "main", "PR target branch")
	c.Flags().StringVar(&remote, "remote", "origin", "push remote for explicit publication")
	return c
}
