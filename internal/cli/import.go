package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/spf13/cobra"
)

func newImportCommand(opts *options) *cobra.Command {
	var failOn string
	cmd := &cobra.Command{
		Use:   "import <sarif-file>...",
		Short: "Bring another tool's SARIF results under securock's policy",
		Long: `Read SARIF 2.1.0 reports from other scanners (CodeQL, Semgrep, Trivy, Checkov and
the like) and handle them like securock's own findings: ranked by severity, accepted
through the exceptions file, and failing the build at --fail-on. Pass - to read stdin.

A finding's ID is sarif:<tool>/<rule>, and its subject is the file it points at, so
"securock accept sarif:semgrep/go.lang.security.audit --subject cmd/x.go" works as
usual. Severity comes from the numeric security-severity property when present, then
the SARIF level; a result with neither is medium. Suppressions inside the SARIF file
are not honored: only the exceptions file accepts a finding. Absolute file paths under the
current directory are made relative to it.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			var found []finding.Finding
			for _, path := range args {
				one, err := readSARIFFile(cmd, path)
				if err != nil {
					return opErr(err)
				}
				found = append(found, one...)
			}
			if root, err := os.Getwd(); err == nil {
				finding.RelativeTo(found, root)
			}
			accepted, err := exceptions.Load(exceptions.Path(".", opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			report := exceptions.Apply(finding.New("import", found), accepted, time.Now().UTC())
			if err := finding.Write(cmd.OutOrStdout(), report, opts.format); err != nil {
				return opErr(err)
			}
			if opts.noFail {
				return nil
			}
			if n := report.AtLeast(threshold); n > 0 {
				return trustErr("findings at or above %s: %d", threshold, n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity: critical, high, medium, low, or info")
	return cmd
}

func readSARIFFile(cmd *cobra.Command, path string) ([]finding.Finding, error) {
	var r io.Reader = cmd.InOrStdin()
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	found, err := finding.ReadSARIF(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return found, nil
}
