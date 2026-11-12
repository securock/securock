package cli

import (
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/spf13/cobra"
	"os"
)

func newControlCommand(opts *options) *cobra.Command {
	var dir, keyEnv, seedEnv, keyFile, seedFile string
	var restore, database, migrate bool
	c := &cobra.Command{Use: "control BACKUP.enc", Short: "Back up or restore authenticated encrypted control-plane state while stopped", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		key, e := serviceSecret(keyEnv, keyFile)
		if e != nil || len(key) != 32 {
			return opErr(fmt.Errorf("invalid encryption key"))
		}
		seed, e := serviceSecret(seedEnv, seedFile)
		if e != nil || len(seed) != 32 {
			return opErr(fmt.Errorf("invalid audit signing seed"))
		}
		if migrate && (restore || database) {
			return opErr(fmt.Errorf("migration cannot be combined with restore or database restore"))
		}
		if migrate {
			return opErr(control.MigrateDatabase(dir, a[0], key, seed))
		}
		if database && !restore {
			return opErr(fmt.Errorf("--database requires --restore"))
		}
		if restore && database {
			return opErr(control.RestoreDatabase(a[0], dir, key, seed))
		}
		if restore {
			return opErr(control.Restore(a[0], dir, key, seed))
		}
		if _, e = os.Stat(dir + string(os.PathSeparator) + "state.enc"); e != nil {
			if _, e = os.Stat(dir + string(os.PathSeparator) + "state.db"); e != nil {
				return opErr(e)
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
		if e = s.Backup(a[0]); e != nil {
			return opErr(e)
		}
		fmt.Fprintln(c.OutOrStdout(), "encrypted backup authenticated and written")
		return nil
	}}
	c.Flags().StringVar(&keyFile, "key-file", "", "mounted base64 state key; overrides key environment")
	c.Flags().StringVar(&seedFile, "audit-key-file", "", "mounted base64 signing seed; overrides seed environment")
	c.Flags().StringVar(&dir, "state-dir", ".securock/control", "stopped control-plane state directory")
	c.Flags().StringVar(&keyEnv, "key-env", "SECUROCK_STATE_KEY", "encryption key environment variable")
	c.Flags().StringVar(&seedEnv, "audit-key-env", "SECUROCK_AUDIT_SEED", "signing seed environment variable")
	c.Flags().BoolVar(&restore, "restore", false, "restore to an absent destination directory")
	c.Flags().BoolVar(&migrate, "migrate-database", false, "migrate authenticated stopped state into an absent database directory supplied as the argument")
	c.Flags().BoolVar(&database, "database", false, "restore an encrypted database backup instead of a legacy snapshot")
	return c
}
