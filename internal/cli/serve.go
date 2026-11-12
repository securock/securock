package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/identity"
	"github.com/spf13/cobra"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func newServeCommand(opts *options) *cobra.Command {
	var listen, dir, keyEnv, cert, key, auditEnv string
	var local bool
	c := &cobra.Command{Use: "serve OIDC.json", Short: "Run the authenticated, tenant-isolated control plane", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if opts.offline || opts.network == "offline" {
			return opErr(fmt.Errorf("serve requires explicit networking"))
		}
		raw, e := os.ReadFile(a[0])
		if e != nil {
			return opErr(e)
		}
		var id identity.Config
		if e = json.Unmarshal(raw, &id); e != nil {
			return opErr(e)
		}
		if e = id.Validate(); e != nil {
			return opErr(e)
		}
		host, _, e := net.SplitHostPort(listen)
		if e != nil {
			return opErr(e)
		}
		ip := net.ParseIP(host)
		if (cert == "" || key == "") && (!local || ip == nil || !ip.IsLoopback()) {
			return opErr(fmt.Errorf("TLS certificate and key required; --local-http permits only literal loopback"))
		}
		material, e := base64.StdEncoding.DecodeString(os.Getenv(keyEnv))
		if e != nil || len(material) != 32 {
			return opErr(fmt.Errorf("key environment variable must contain a base64 32-byte key"))
		}
		store, e := control.Open(dir, material, id.Bindings)
		if e != nil {
			return opErr(e)
		}
		defer store.Close()
		seed, err := base64.StdEncoding.DecodeString(os.Getenv(auditEnv))
		if err != nil {
			return opErr(fmt.Errorf("invalid audit seed"))
		}
		if err = store.SetSigner(seed); err != nil {
			return opErr(err)
		}
		ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		srv := &http.Server{Addr: listen, Handler: &control.Server{Store: store, Identity: id}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdown)
			case <-done:
			}
		}()
		if cert != "" && key != "" {
			e = srv.ListenAndServeTLS(cert, key)
		} else {
			e = srv.ListenAndServe()
		}
		if e == http.ErrServerClosed {
			return nil
		}
		return opErr(e)
	}}
	c.Flags().StringVar(&auditEnv, "audit-key-env", "SECUROCK_AUDIT_SEED", "base64 Ed25519 32-byte seed from a separate secret")
	c.Flags().StringVar(&listen, "listen", "127.0.0.1:8443", "listen address")
	c.Flags().StringVar(&dir, "state-dir", ".securock/control", "private encrypted state directory")
	c.Flags().StringVar(&keyEnv, "key-env", "SECUROCK_STATE_KEY", "base64 32-byte encryption key environment variable")
	c.Flags().StringVar(&cert, "tls-cert", "", "TLS certificate path")
	c.Flags().StringVar(&key, "tls-key", "", "TLS key path")
	c.Flags().BoolVar(&local, "local-http", false, "allow unencrypted literal-loopback development only")
	return c
}
