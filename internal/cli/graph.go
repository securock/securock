package cli

import (
	"fmt"

	"github.com/securock/securock/internal/graph"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	"github.com/spf13/cobra"
)

func newGraphCommand(opts *options) *cobra.Command {
	var problems bool
	cmd := &cobra.Command{
		Use:   "graph [path]",
		Short: "Draw the dependency graph, colored by trust status",
		Long: `Draw the dependency graph read from the lockfiles, with the trust status of each
package. --format text (default) prints a tree, mermaid and dot print a diagram that
GitHub, GitLab and Graphviz can render.

--problems keeps only the packages that are untrusted or unknown, and the packages that
lead to them, to show why each one is in the project.

Dependency edges come from the lockfile, and not every ecosystem records them; see the
reachability table in the ecosystems guide. When none are recorded the graph lists top-level
packages only, and says so.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := policy.LoadWithProfile(opts.policy, opts.profile)
			if err != nil {
				return opErr(err)
			}
			net, err := scanOptions(opts, pol)
			if err != nil {
				return err
			}
			result, err := scanner.Scan(cmd.Context(), scanner.Options{
				Path:    projectPath(args),
				Offline: opts.offline,
				Network: net,
				Policy:  pol,
				// Edges are only recorded by a reachability scan.
				Reachability: true,
			})
			if err != nil {
				return opErr(err)
			}
			g := graph.Build(result.Document)
			if problems {
				g = g.Problems()
			}
			if !g.HasEdges && len(g.Nodes) > 0 && opts.format != "text" && opts.format != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "the lockfile records no dependency edges, so the graph has no connections")
			}
			if err := graph.Write(cmd.OutOrStdout(), g, opts.format); err != nil {
				return opErr(err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&problems, "problems", false, "show only untrusted and unknown packages and the packages that lead to them")
	return cmd
}
