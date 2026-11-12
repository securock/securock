package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/spf13/cobra"
	"os"
)

func newEvidenceCommand(opts *options) *cobra.Command {
	var key string
	c := &cobra.Command{Use: "evidence AUDIT.json", Short: "Verify a signed audit chain against an independently pinned public key", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		raw, e := os.ReadFile(a[0])
		if e != nil {
			return opErr(e)
		}
		var v control.AuditExport
		if e = json.Unmarshal(raw, &v); e != nil {
			return opErr(e)
		}
		public, e := base64.StdEncoding.DecodeString(key)
		if e != nil {
			return opErr(fmt.Errorf("invalid public key"))
		}
		if e = control.VerifyAudit(v, ed25519.PublicKey(public)); e != nil {
			return opErr(e)
		}
		fmt.Fprintln(c.OutOrStdout(), "audit chain verified; compare sequence with independently retained checkpoints to detect truncation")
		return nil
	}}
	c.Flags().StringVar(&key, "public-key", "", "independently trusted base64 Ed25519 public key")
	return c
}
