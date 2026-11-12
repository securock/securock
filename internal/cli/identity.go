package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/identity"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func newIdentityCommand(opts *options) *cobra.Command {
	var env string
	c := &cobra.Command{Use: "identity CONFIG.json", Short: "Verify an OIDC API access token and display its bound tenant and roles", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		f, e := os.Open(a[0])
		if e != nil {
			return opErr(e)
		}
		defer f.Close()
		var conf identity.Config
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		if e = d.Decode(&conf); e != nil {
			return opErr(e)
		}
		if e = conf.Validate(); e != nil {
			return opErr(e)
		}
		token := os.Getenv(env)
		if token == "" {
			return opErr(fmt.Errorf("token environment variable is empty"))
		}
		p, e := conf.Verify(token, time.Now())
		if e != nil {
			return opErr(e)
		}
		return opErr(json.NewEncoder(c.OutOrStdout()).Encode(p))
	}}
	c.Flags().StringVar(&env, "token-env", "SECUROCK_TOKEN", "environment variable containing an OIDC access token")
	return c
}
