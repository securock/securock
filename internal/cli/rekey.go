package cli

import (
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

func newRekeyCommand(opts *options) *cobra.Command {
	var dir, keyEnv, seedEnv, nextEnv, keyFile, seedFile, nextFile string
	c := &cobra.Command{Use: "control-rekey", Short: "Rotate the encryption key for authenticated stopped control-plane state", Args: cobra.NoArgs, RunE: func(c *cobra.Command, a []string) error {
		key, e := serviceSecret(keyEnv, keyFile)
		if e != nil {
			return opErr(e)
		}
		seed, e := serviceSecret(seedEnv, seedFile)
		if e != nil {
			return opErr(e)
		}
		next, e := serviceSecret(nextEnv, nextFile)
		if e != nil {
			return opErr(e)
		}
		if _, e = os.Stat(filepath.Join(dir, "state.enc")); e != nil {
			if _, e = os.Stat(filepath.Join(dir, "state.db")); e != nil {
				return opErr(fmt.Errorf("existing state required for key rotation"))
			}
		}
		s, e := control.Open(dir, key, nil)
		if e != nil {
			return opErr(e)
		}
		defer s.Close()
		if e = s.SetSigner(seed); e != nil {
			return opErr(e)
		}
		if e = s.Rekey(next); e != nil {
			return opErr(e)
		}
		fmt.Fprintln(c.OutOrStdout(), "state encryption key rotated; update service credentials before restart and retain old keys for historical backups")
		return nil
	}}
	c.Flags().StringVar(&dir, "state-dir", ".securock/control", "stopped control-plane state directory")
	c.Flags().StringVar(&keyEnv, "key-env", "SECUROCK_STATE_KEY", "current encryption key environment variable")
	c.Flags().StringVar(&seedEnv, "audit-key-env", "SECUROCK_AUDIT_SEED", "audit signing seed environment variable")
	c.Flags().StringVar(&nextEnv, "new-key-env", "SECUROCK_NEW_STATE_KEY", "new encryption key environment variable")
	c.Flags().StringVar(&keyFile, "key-file", "", "mounted current base64 state key")
	c.Flags().StringVar(&seedFile, "audit-key-file", "", "mounted base64 audit signing seed")
	c.Flags().StringVar(&nextFile, "new-key-file", "", "mounted new base64 state key")
	return c
}
