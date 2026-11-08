package cli

import (
	"fmt"

	"github.com/securock/securock/internal/httpx"
	"github.com/spf13/cobra"
)

func newCacheCommand() *cobra.Command {
	cache := &cobra.Command{
		Use:   "cache",
		Short: "Manage the on-disk cache of registry and OSV responses",
		Long: `Registry and OSV responses are kept on disk for an hour, so repeated runs (a pre-commit
hook, --recursive, CI retries) do not ask again. Use --no-cache on any command to skip the
cache for one run, and --cache-ttl to change how long a response is used.`,
	}
	cache.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Delete every cached response",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := httpx.Clear()
			if err != nil {
				return opErr(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d cached responses\n", n)
			return nil
		},
	})
	return cache
}
