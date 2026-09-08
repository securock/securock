package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/spf13/cobra"
)

func newScanCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project and evaluate dependency trust",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, opts, projectPath(args))
		},
	}
	return cmd
}

func runScan(cmd *cobra.Command, opts *options, path string) error {
	pol, err := policy.Load(opts.policy)
	if err != nil {
		return opErr(err)
	}
	net, err := scanOptions(opts, pol)
	if err != nil {
		return err
	}

	result, err := scanner.Scan(cmd.Context(), scanner.Options{
		Path:    path,
		Offline: opts.offline,
		Network: net,
		Policy:  pol,
	})
	if err != nil {
		return opErr(err)
	}

	if err := writeScan(cmd.OutOrStdout(), result.Document, opts.format); err != nil {
		return opErr(err)
	}

	_, untrusted, unknown := scanner.Summary(result.Document)
	if opts.noFail {
		return nil
	}
	if untrusted > 0 {
		return trustErr("untrusted artifacts: %d", untrusted)
	}
	if unknown > 0 {
		return trustErr("unknown artifacts: %d", unknown)
	}
	return nil
}

func writeScan(w io.Writer, doc lockfile.Document, format string) error {
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	case "text", "":
		return writeScanText(w, doc)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeScanText(w io.Writer, doc lockfile.Document) error {
	trusted, untrusted, unknown := scanner.Summary(doc)
	fmt.Fprintf(w, "ecosystems  %s\n", strings.Join(doc.Source.Ecosystems, ", "))
	if len(doc.Source.Resolvers) > 0 {
		fmt.Fprintf(w, "resolvers   %s\n", strings.Join(doc.Source.Resolvers, ", "))
	}
	fmt.Fprintf(w, "artifacts   %d\n", len(doc.Artifacts))
	fmt.Fprintf(w, "trusted     %d\n", trusted)
	fmt.Fprintf(w, "untrusted   %d\n", untrusted)
	fmt.Fprintf(w, "unknown     %d\n", unknown)

	if untrusted > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "untrusted artifacts:")
		for _, art := range doc.Artifacts {
			if art.Trust.Status != lockfile.StatusUntrusted {
				continue
			}
			ids := make([]string, 0, len(art.Evidence.Vulnerabilities.Items))
			for _, v := range art.Evidence.Vulnerabilities.Items {
				ids = append(ids, v.ID)
			}
			extra := strings.Join(art.Trust.Reasons, ", ")
			if len(ids) > 0 {
				extra = extra + "  " + strings.Join(ids, ", ")
			}
			fmt.Fprintf(w, "  %s  %s@%s  %s\n", art.Subject.Ecosystem, art.Subject.Name, art.Version, strings.TrimSpace(extra))
		}
	}
	return nil
}
