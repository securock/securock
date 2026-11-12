package cli

import (
	"encoding/base64"
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/spf13/cobra"
	"os"
)

func newControlCommand(opts *options) *cobra.Command {
	var dir, keyEnv, seedEnv string
	var restore bool
	c := &cobra.Command{Use: "control BACKUP.enc", Short: "Back up or restore authenticated encrypted control-plane state while stopped", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		key, e := base64.StdEncoding.DecodeString(os.Getenv(keyEnv))
		if e != nil || len(key) != 32 {
			return opErr(fmt.Errorf("invalid encryption key"))
		}
		seed, e := base64.StdEncoding.DecodeString(os.Getenv(seedEnv))
		if e != nil || len(seed) != 32 {
			return opErr(fmt.Errorf("invalid audit signing seed"))
		}
		if restore {
			return opErr(control.Restore(a[0], dir, key, seed))
		}
		if _, e = os.Stat(dir); e != nil {
			return opErr(e)
		}
		s, e := control.Open(dir, key, nil)
		if e != nil {
			return opErr(e)
		}
		defer s.Close()
		if e = s.SetSigner(seed); e != nil {
			return opErr(e)
		}
		if e = s.Backup(a[0]); e != nil {
			return opErr(e)
		}
		fmt.Fprintln(c.OutOrStdout(), "encrypted backup authenticated and written")
		return nil
	}}
	c.Flags().StringVar(&dir, "state-dir", ".securock/control", "stopped control-plane state directory")
	c.Flags().StringVar(&keyEnv, "key-env", "SECUROCK_STATE_KEY", "encryption key environment variable")
	c.Flags().StringVar(&seedEnv, "audit-key-env", "SECUROCK_AUDIT_SEED", "signing seed environment variable")
	c.Flags().BoolVar(&restore, "restore", false, "restore to an absent destination directory")
	return c
}
