package cli

import (
	"time"

	"github.com/securock/securock/internal/chain"
	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/sast"
	"github.com/spf13/cobra"
)

func newChainCommand(opts *options) *cobra.Command {
	var failOn string
	var assumeParams bool
	cmd := &cobra.Command{
		Use:   "chain [path]",
		Short: "Correlate source findings into attack chains",
		Long: `Correlate the findings of securock sast into attack chains: where attacker-
controlled data enters the application, which dangerous operations it reaches, and
which committed credentials an attacker could read on the way.

A chain comes either from one dataflow finding whose trace proves the whole path, or
from several findings that share a file. A link is confirmed only when both findings
are proven inside the same function; sharing a file alone makes the chain possible,
and it never fails a build. Analysis is offline and deterministic.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			threshold, err := finding.ParseSeverity(failOn)
			if err != nil {
				return opErr(err)
			}
			path := projectPath(args)
			found, err := sast.AnalyzeWith(path, sast.Options{AssumeParams: assumeParams})
			if err != nil {
				return opErr(err)
			}
			accepted, err := exceptions.Load(exceptions.Path(path, opts.exceptions))
			if err != nil {
				return opErr(err)
			}
			report := exceptions.Apply(finding.New("sast", found), accepted, time.Now().UTC())
			report2 := chain.Report{Tool: "chain", Chains: chain.Analyze(report.Findings)}
			if err := chain.Write(cmd.OutOrStdout(), report2, opts.format); err != nil {
				return opErr(err)
			}
			if opts.noFail {
				return nil
			}
			if n := report2.AtLeast(threshold); n > 0 {
				return trustErr("confirmed chains at or above %s: %d", threshold, n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit 1 when a confirmed chain is at or above this severity: critical, high, medium, low, or info")
	cmd.Flags().BoolVar(&assumeParams, "assume-params", false, "treat string parameters of Go functions that nothing calls directly as untrusted, as securock sast does")
	return cmd
}
