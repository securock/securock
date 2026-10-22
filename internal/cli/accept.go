package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/securock/securock/internal/exceptions"
	pkgexceptions "github.com/securock/securock/pkg/exceptions"
	"github.com/spf13/cobra"
)

func newAcceptCommand(opts *options) *cobra.Command {
	var (
		subject  string
		reason   string
		approver string
		expires  string

		justification string
	)
	cmd := &cobra.Command{
		Use:   "accept FINDING-ID [path]",
		Short: "Accept a finding until a date, with a reason",
		Long: "Record that a finding is accepted, so audit reports it as suppressed until the date passes.\n" +
			"FINDING-ID is the id shown by audit, such as known-vulnerability:GHSA-xxxx or capability:network.\n" +
			"Exceptions live in .securock/exceptions.yaml and never change securock.lock.\n" +
			"Accepting the same finding and package again renews it.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			now := time.Now().UTC()
			until, err := parseExpiry(expires, now)
			if err != nil {
				return opErr(err)
			}
			e := pkgexceptions.Exception{ID: args[0], Subject: subject, Reason: reason, Approver: approver, Expires: until, Justification: justification}
			if err := pkgexceptions.Validate(pkgexceptions.Document{Version: pkgexceptions.SchemaVersion, Exceptions: []pkgexceptions.Exception{e}}); err != nil {
				return opErr(err)
			}
			if e.Expired(now) {
				return opErr(fmt.Errorf("--expires %s is in the past", until))
			}

			path := exceptions.Path(projectPath(args[1:]), opts.exceptions)
			doc, err := exceptions.Load(path)
			if err != nil {
				return opErr(err)
			}
			doc, renewed := exceptions.Upsert(doc, e)
			if err := exceptions.Save(path, doc); err != nil {
				return opErr(err)
			}
			verb := "accepted"
			if renewed {
				verb = "renewed"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s until %s in %s\n", verb, describe(e), until, path)
			return nil
		},
	}
	cmd.Flags().StringVar(&subject, "subject", "", "limit to one package: ecosystem:name@version, or ecosystem:name for any version")
	cmd.Flags().StringVar(&reason, "reason", "", "why the finding is acceptable (required)")
	cmd.Flags().StringVar(&approver, "approver", "", "who approved the exception")
	cmd.Flags().StringVar(&expires, "expires", "", "last day it applies: YYYY-MM-DD, or a number of days such as 90d (required)")
	cmd.Flags().StringVar(&justification, "justification", "", "for a vulnerability, say it does not affect you instead of accepting the risk: "+strings.Join(pkgexceptions.Justifications, ", "))
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("expires")

	cmd.AddCommand(newAcceptListCommand(opts), newAcceptRemoveCommand(opts))
	return cmd
}

func newAcceptListCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list [path]",
		Short: "List accepted findings and whether they are still active",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := exceptions.Path(projectPath(args), opts.exceptions)
			doc, err := exceptions.Load(path)
			if err != nil {
				return opErr(err)
			}
			doc = pkgexceptions.Canonicalize(doc)
			now := time.Now().UTC()

			if strings.ToLower(opts.format) == "json" {
				type row struct {
					pkgexceptions.Exception
					Status string `json:"status"`
				}
				rows := make([]row, 0, len(doc.Exceptions))
				for _, e := range doc.Exceptions {
					rows = append(rows, row{e, status(e, now)})
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if opts.format != "" && strings.ToLower(opts.format) != "text" {
				return opErr(fmt.Errorf("unsupported format %q", opts.format))
			}
			if len(doc.Exceptions) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no accepted findings")
				return nil
			}
			for _, e := range doc.Exceptions {
				line := fmt.Sprintf("%-8s until %s  %s", status(e, now), e.Expires, describe(e))
				if e.Approver != "" {
					line += "  by " + e.Approver
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n         %s\n", line, e.Reason)
			}
			return nil
		},
	}
}

func newAcceptRemoveCommand(opts *options) *cobra.Command {
	var subject string
	cmd := &cobra.Command{
		Use:   "remove FINDING-ID [path]",
		Short: "Stop accepting a finding",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := exceptions.Path(projectPath(args[1:]), opts.exceptions)
			doc, err := exceptions.Load(path)
			if err != nil {
				return opErr(err)
			}
			doc, removed := exceptions.Remove(doc, args[0], subject)
			if !removed {
				return opErr(fmt.Errorf("no exception for %s", describe(pkgexceptions.Exception{ID: args[0], Subject: subject})))
			}
			if err := exceptions.Save(path, doc); err != nil {
				return opErr(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", describe(pkgexceptions.Exception{ID: args[0], Subject: subject}))
			return nil
		},
	}
	cmd.Flags().StringVar(&subject, "subject", "", "the package the exception was limited to, if any")
	return cmd
}

// parseExpiry accepts a YYYY-MM-DD date or a day count such as 90d.
func parseExpiry(s string, now time.Time) (string, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 {
			return "", fmt.Errorf("--expires %q: use a date (YYYY-MM-DD) or a positive number of days such as 90d", s)
		}
		return now.AddDate(0, 0, n).Format(pkgexceptions.DateLayout), nil
	}
	if _, err := time.Parse(pkgexceptions.DateLayout, s); err != nil {
		return "", fmt.Errorf("--expires %q: use a date (YYYY-MM-DD) or a positive number of days such as 90d", s)
	}
	return s, nil
}

func status(e pkgexceptions.Exception, now time.Time) string {
	if e.Expired(now) {
		return "expired"
	}
	return "active"
}

func describe(e pkgexceptions.Exception) string {
	if e.Subject == "" {
		return e.ID
	}
	return e.ID + " for " + e.Subject
}
