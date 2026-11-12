package cli

import (
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/credential"
	"github.com/spf13/cobra"
	"os"
)

func newCredentialCommand(opts *options) *cobra.Command {
	var action, origin, env, clientID, secretEnv, replacement string
	c := &cobra.Command{Use: "credential PROVIDER", Short: "Explicitly check, revoke or rotate an operator-supplied provider token", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if opts.offline || opts.network != "allow-all" {
			return opErr(fmt.Errorf("credential operations require --network allow-all"))
		}
		if origin == "" {
			switch a[0] {
			case "github":
				origin = "https://api.github.com"
			case "gitlab":
				origin = "https://gitlab.com"
			}
		}
		var f *os.File
		var e error
		if action == "rotate" {
			if replacement == "" {
				return opErr(fmt.Errorf("rotation requires --replacement-file"))
			}
			f, e = os.OpenFile(replacement, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return opErr(e)
			}
			defer f.Close()
		}
		r, operationErr := credential.Execute(c.Context(), credential.Options{Provider: a[0], Action: action, Origin: origin, Token: os.Getenv(env), ClientID: clientID, ClientSecret: os.Getenv(secretEnv), Replacement: f})
		if f != nil {
			if e = f.Sync(); e != nil {
				return opErr(e)
			}
		}
		if e = json.NewEncoder(c.OutOrStdout()).Encode(r); e != nil {
			return opErr(e)
		}
		if operationErr != nil {
			return opErr(operationErr)
		}
		return nil
	}}
	c.Flags().StringVar(&action, "action", "check", "check, revoke or rotate; mutation requires explicit selection")
	c.Flags().StringVar(&origin, "origin", "", "explicit HTTPS API origin for self-hosted providers")
	c.Flags().StringVar(&env, "token-env", "SECUROCK_CREDENTIAL", "provider token environment variable")
	c.Flags().StringVar(&clientID, "client-id", "", "owning GitHub OAuth application client ID")
	c.Flags().StringVar(&secretEnv, "client-secret-env", "SECUROCK_OAUTH_SECRET", "owning OAuth app secret environment variable")
	c.Flags().StringVar(&replacement, "replacement-file", "", "exclusive private file for a newly rotated token")
	return c
}
