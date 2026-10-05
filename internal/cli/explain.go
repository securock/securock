package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/securock/securock/internal/explain"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newExplainCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "explain <package> [path]",
		Short: "Explain why a dependency is trusted",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkg := args[0]
			path := "."
			if len(args) == 2 {
				path = args[1]
			}

			pol, err := policy.LoadWithProfile(opts.policy, opts.profile)
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

			got, err := explain.Find(result.Document, pkg)
			if err != nil {
				return opErr(err)
			}

			switch strings.ToLower(opts.format) {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(got.Artifacts)
			case "text", "":
				explain.Write(cmd.OutOrStdout(), got)
				return nil
			default:
				return opErr(fmt.Errorf("unsupported format %q", opts.format))
			}
		},
	}
}
