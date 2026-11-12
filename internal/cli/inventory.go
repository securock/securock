package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/inventory"
	"github.com/spf13/cobra"
	"os"
)

func newInventoryCommand(opts *options) *cobra.Command {
	var file string
	var collect bool
	c := &cobra.Command{Use: "inventory [ROOT]", Short: "Discover repositories and correlate observed Kubernetes image digests", Args: cobra.MaximumNArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if file != "" && collect {
			return opErr(fmt.Errorf("choose a pod export or live collection"))
		}
		var pods []byte
		var e error
		if collect {
			if opts.offline || opts.network != "allow-all" {
				return opErr(fmt.Errorf("live inventory requires --network allow-all"))
			}
			pods, e = external.Run(c.Context(), "kubectl", "get", "pods", "--all-namespaces", "-o", "json")
		} else if file != "" {
			pods, e = os.ReadFile(file)
		}
		if e != nil {
			return opErr(e)
		}
		r, e := inventory.Discover(c.Context(), projectPath(a), pods)
		if e != nil {
			return opErr(e)
		}
		return opErr(json.NewEncoder(c.OutOrStdout()).Encode(r))
	}}
	c.Flags().StringVar(&file, "pods", "", "local Kubernetes PodList JSON")
	c.Flags().BoolVar(&collect, "collect-kubernetes", false, "read pods using the operator's current kubectl context")
	return c
}
