package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/baseline"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/validation"
	"github.com/spf13/cobra"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
)

func newIntegrationCommand(opts *options) *cobra.Command {
	var local bool
	c := &cobra.Command{Use: "integration [suite.json]", Short: "Validate scanners against reproducible fixtures or an explicit integration suite", Args: cobra.MaximumNArgs(1), RunE: func(c *cobra.Command, a []string) error {
		if local == (len(a) > 0) {
			return opErr(fmt.Errorf("choose --local or one suite JSON file"))
		}
		pol, e := policy.LoadWithProfile(opts.policy, opts.profile)
		if e != nil {
			return opErr(e)
		}
		net, e := scanOptions(opts, pol)
		if e != nil {
			return e
		}
		suite := validation.Suite{Version: 1}
		if local {
			if opts.offline || net.ResolvedMode() == "offline" {
				return opErr(fmt.Errorf("local HTTP validation needs loopback networking"))
			}
			dir, e := os.MkdirTemp("", "securock-lab-*")
			if e != nil {
				return opErr(e)
			}
			defer os.RemoveAll(dir)
			source := []byte("package main\nimport \"crypto/tls\"\nfunc f(){ _ = tls.Config{InsecureSkipVerify: true} }\n")
			if e := os.WriteFile(filepath.Join(dir, "main.go"), source, 0600); e != nil {
				return opErr(e)
			}
			inventory := filepath.Join(dir, "cloud.json")
			if e := os.WriteFile(inventory, []byte(`{"configurationItems":[{"resourceType":"AWS::RDS::DBInstance","resourceId":"db-fixture","accountId":"123456789012","awsRegion":"us-east-1","configuration":{"publiclyAccessible":true,"storageEncrypted":true,"backupRetentionPeriod":7}}]}`), 0600); e != nil {
				return opErr(e)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("<html>fixture</html>"))
			}))
			defer server.Close()
			suite.Steps = []validation.Step{{Name: "source-and-cloud", Command: "security", Args: []string{dir, "--offline", "--cloud-inventory", inventory}, Expected: []string{"sast:go/tls-verification-disabled", "cspm:rds-public"}}, {Name: "live-http", Command: "dast", Args: []string{server.URL}, Expected: []string{"dast:unencrypted-http", "dast:csp-missing"}}}
		} else {
			f, e := os.Open(a[0])
			if e != nil {
				return opErr(e)
			}
			suite, e = validation.Read(f)
			f.Close()
			if e != nil {
				return opErr(e)
			}
		}
		result := validation.Report{Version: 1, Results: []validation.Result{}}
		failed := false
		for _, step := range suite.Steps {
			args := append([]string{step.Command}, step.Args...)
			mode := string(net.ResolvedMode())
			if local {
				mode = "allow-all"
			}
			args = append(args, "--network", mode, "--format", "json", "--no-fail")
			if opts.offline {
				args = append(args, "--offline")
			}
			root := NewRoot(opts.toolVersion, "integration", "")
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(c.ErrOrStderr())
			root.SetIn(bytes.NewReader(nil))
			root.SetContext(c.Context())
			root.SetArgs(args)
			scanErr := root.Execute()
			r, readErr := baseline.Read(bytes.NewReader(out.Bytes()))
			if readErr != nil {
				scanErr = readErr
			}
			item := validation.Evaluate(step, r, scanErr)
			result.Results = append(result.Results, item)
			if !item.Passed {
				failed = true
			}
		}
		if opts.format == "json" {
			if e := json.NewEncoder(c.OutOrStdout()).Encode(result); e != nil {
				return opErr(e)
			}
		} else if opts.format == "text" {
			for _, r := range result.Results {
				fmt.Fprintf(c.OutOrStdout(), "%s passed=%t missing=%v unexpected=%v operational_error=%t\n", r.Name, r.Passed, r.Missing, r.Unexpected, r.OperationalError)
			}
		} else {
			return opErr(fmt.Errorf("integration supports text or json"))
		}
		if failed {
			return trustErr("integration validation failed")
		}
		return nil
	}}
	c.Flags().BoolVar(&local, "local", false, "run built-in source, cloud-export, and local HTTP fixtures without external services")
	return c
}
