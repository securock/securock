package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/securock/securock/internal/diff"
	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newUpdateCommand(opts *options) *cobra.Command {
	var write bool
	cmd := &cobra.Command{
		Use:   "update [path]",
		Short: "Review trust changes after a dependency update, then refresh securock.lock",
		Long: "Scan the project, show how its trust state differs from securock.lock, and with --write record the new state.\n" +
			"Without --write nothing on disk changes, so the report is a preview to review.\n" +
			"--write refuses to record a state with untrusted or unknown artifacts; add --no-fail to record it anyway.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format := strings.ToLower(opts.format)
			if format != "text" && format != "json" && format != "" {
				return opErr(fmt.Errorf("update supports --format text or json, not %q", opts.format))
			}

			path := projectPath(args)
			pol, err := policy.LoadWithProfile(opts.policy, opts.profile)
			if err != nil {
				return opErr(err)
			}
			net, err := scanOptions(opts, pol)
			if err != nil {
				return err
			}

			lockPath := lock.Path(path, opts.lockPath)
			locked, migrated, err := lock.Read(lockPath)
			if err != nil {
				return opErr(fmt.Errorf("%w; run 'securock lock' to create the first securock.lock", err))
			}
			if migrated {
				fmt.Fprintln(cmd.ErrOrStderr(), lock.MigrationWarning)
			}

			result, err := scanner.Scan(cmd.Context(), scanner.Options{
				Path:         path,
				Offline:      opts.offline,
				Network:      net,
				Policy:       pol,
				Reachability: opts.reachability,
			})
			if err != nil {
				return opErr(err)
			}

			got := diff.Compare(locked, result.Document).WithPolicy(pol)
			if err := writeDiff(cmd, got, opts.format, ""); err != nil {
				return opErr(err)
			}

			// Status lines go to stderr when stdout carries JSON.
			status := cmd.OutOrStdout()
			if format == "json" {
				status = cmd.ErrOrStderr()
			}

			next, err := lock.Encode(lockPath, result.Document)
			if err != nil {
				return opErr(err)
			}
			current, err := os.ReadFile(lockPath)
			if err != nil {
				return opErr(err)
			}
			if !migrated && bytes.Equal(current, next) {
				fmt.Fprintf(status, "\n%s is up to date\n", lockPath)
				return nil
			}
			if !write {
				fmt.Fprintf(status, "\n%s was not changed; review the report, then run 'securock update --write' to record it\n", lockPath)
				return nil
			}

			_, untrusted, unknown := scanner.Summary(result.Document)
			if !opts.noFail {
				if untrusted > 0 {
					return trustErr("not writing %s: untrusted artifacts: %d", lockPath, untrusted)
				}
				if unknown > 0 {
					return trustErr("not writing %s: unknown artifacts: %d", lockPath, unknown)
				}
			}
			if err := os.WriteFile(lockPath, next, 0o644); err != nil {
				return opErr(err)
			}
			fmt.Fprintf(status, "\nwrote %s\n", lockPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&write, "write", false, "record the new trust state in securock.lock")
	return cmd
}
