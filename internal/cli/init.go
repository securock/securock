package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/policy"
	"github.com/securock/securock/internal/scanner"
	pkgpolicy "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const policyFile = ".securock/policy.yaml"

func newInitCommand(opts *options) *cobra.Command {
	var writePolicy bool
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Set up securock in a project: write the first securock.lock",
		Long: `Detect the project's lockfiles, record the current trust state in securock.lock, and say
what to do next. It is the first run of 'securock lock' plus a summary, and refuses to
overwrite an existing securock.lock: use 'securock lock' to refresh one.

--write-policy also writes the policy profile in use (--profile, default or strict) to
.securock/policy.yaml, so you can edit it. Pass that file with --policy afterwards.

Like 'lock', init exits 1 when the snapshot has untrusted or unknown artifacts, which is
expected on a first offline run: the files are still written. Use --no-fail to exit 0.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := projectPath(args)
			if writePolicy && opts.policy != "" {
				return opErr(fmt.Errorf("--write-policy writes a built-in profile; drop --policy, or choose the profile with --profile"))
			}
			found := ecosystem.Detect(path)
			if len(found) == 0 {
				return opErr(fmt.Errorf("no supported lockfile found in %s", path))
			}

			lockPath := lock.Path(path, opts.lockPath)
			polPath := filepath.Join(path, filepath.FromSlash(policyFile))
			if _, err := os.Stat(lockPath); err == nil {
				return opErr(fmt.Errorf("%s already exists; run 'securock lock' to refresh it", lockPath))
			}
			if _, err := os.Stat(polPath); writePolicy && err == nil {
				return opErr(fmt.Errorf("%s already exists; remove it or drop --write-policy", polPath))
			}

			pol, err := policy.LoadWithProfile(opts.policy, opts.profile)
			if err != nil {
				return opErr(err)
			}
			net, err := scanOptions(opts, pol)
			if err != nil {
				return err
			}
			result, err := scanner.Scan(cmd.Context(), scanner.Options{Attestations: opts.attestations, SignerKey: opts.signerKey,
				Path:         path,
				Offline:      opts.offline,
				Network:      net,
				Policy:       pol,
				Reachability: opts.reachability,
			})
			if err != nil {
				return opErr(err)
			}

			out := cmd.OutOrStdout()
			names := make([]string, 0, len(found))
			for _, e := range found {
				names = append(names, e.Name())
			}
			fmt.Fprintf(out, "detected %s\n", strings.Join(names, ", "))

			if err := lock.Write(lockPath, result.Document); err != nil {
				return opErr(err)
			}
			fmt.Fprintf(out, "wrote %s\n", lockPath)
			verify := "securock verify"
			if path != "." {
				verify += " " + path
			}
			if writePolicy {
				if err := writePolicyFile(polPath, pol); err != nil {
					return opErr(err)
				}
				fmt.Fprintf(out, "wrote %s\n", polPath)
				verify += " --policy " + filepath.ToSlash(polPath)
			} else if opts.policy != "" {
				verify += " --policy " + opts.policy
			}

			trusted, untrusted, unknown := scanner.Summary(result.Document)
			fmt.Fprintf(out, "%d artifacts: %d trusted, %d untrusted, %d unknown\n", len(result.Document.Artifacts), trusted, untrusted, unknown)
			if unknown > 0 {
				fmt.Fprintln(out, "unknown means the evidence was not collected (offline, or not available for that ecosystem); it is not a claim that the package is safe.")
			}
			fmt.Fprintf(out, "\nnext:\n  commit securock.lock\n  %s    # in CI, fails when dependencies drift\n  securock update               # after a dependency change, review and accept it\n  securock audit                # findings ranked by severity\n", verify)

			if opts.noFail {
				return nil
			}
			if untrusted > 0 {
				return trustErr("untrusted artifacts: %d", untrusted)
			}
			if unknown > 0 {
				return trustErr("unknown artifacts: %d", unknown)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&writePolicy, "write-policy", false, "also write the policy profile in use to "+policyFile)
	return cmd
}

func writePolicyFile(path string, doc pkgpolicy.Document) error {
	var buf bytes.Buffer
	buf.WriteString("# Securock policy. Pass it with --policy. Unknown fields are errors.\n# https://securock.dev/guide/policy\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
