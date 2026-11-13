package cli

import (
	"path/filepath"
	"time"

	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/progress"
	"github.com/securock/securock/internal/sast"
	"github.com/spf13/cobra"
)

func newSASTCommand(opts *options) *cobra.Command {
	var failOn string
	var assumeParams bool
	var imports []string
	cmd := &cobra.Command{
		Use:   "sast [path]",
		Short: "Find vulnerabilities in your own source code",
		Long: `Analyze the project's source for untrusted data that reaches a dangerous call
(SQL, command and code injection, path traversal, SSRF, XSS, open redirect, insecure
deserialization) and, in Go, for insecure API use (weak crypto, disabled TLS
verification, hard-coded credentials).

Languages: Go, JavaScript and TypeScript, Python, Java, Kotlin, C#, PHP, and Ruby. Data is followed
across assignments, fields, setters, direct local reference aliases, closures, function
calls and files. Deep calls and loop-carried data are followed to convergence within
bounded analysis budgets. Analysis is offline. A
file that cannot be parsed is reported as sast:analysis-incomplete rather than skipped
silently. React's dangerouslySetInnerHTML is a sink in JSX and TSX. Dockerfiles,
Kubernetes and Compose manifests, Terraform, and GitHub Actions workflows are checked for
unsafe settings (sast:iac/*), and text files are scanned for committed credentials
(sast:secrets/*). Packages the repository ships in vendor/, node_modules/ or
site-packages/ are analyzed as well, so a helper in an installed package is followed
into the API it calls; the package's own findings are not reported.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			path := projectPath(args)
			found, err := sast.AnalyzeWith(path, sast.Options{AssumeParams: assumeParams, Progress: func(stage string) { progress.Report(cmd.Context(), stage) }})
			if err != nil {
				return opErr(err)
			}
			external, err := importedFindings(cmd, path, imports)
			if err != nil {
				return opErr(err)
			}
			found = append(found, external...)
			accepted, err := exceptions.Load(exceptions.Path(path, opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			report := exceptions.Apply(finding.New("sast", found), accepted, time.Now().UTC())
			if err := finding.Write(cmd.OutOrStdout(), report, opts.format); err != nil {
				return opErr(err)
			}
			if err := incompleteErr(report); err != nil {
				return err
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
	cmd.Flags().StringArrayVar(&imports, "import", nil, "also include the findings of a SARIF 2.1.0 report from another scanner (repeatable; - reads stdin); they are ranked, accepted and failed on like the sast findings, with IDs of the form sarif:<tool>/<rule>")
	cmd.Flags().BoolVar(&assumeParams, "assume-params", false, "treat string parameters of Go functions that nothing calls directly as untrusted (handlers reached through a registry); finds more, with more false positives")
	return cmd
}

// importedFindings reads the SARIF reports given with --import, with file paths made
// relative to the project so they read like sast's own.
func importedFindings(cmd *cobra.Command, project string, files []string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, file := range files {
		found, err := readSARIFFile(cmd, file)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	if abs, err := filepath.Abs(project); err == nil {
		finding.RelativeTo(out, abs)
	}
	return out, nil
}
