package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/securock/securock/internal/httpx"
	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
)

type options struct {
	toolVersion string
	offline     bool
	network     string
	format      string
	lockPath    string
	policy      string
	profile     string
	noFail      bool
	output      string

	exceptions string

	reachability bool
	recursive    bool
	noCache      bool
	cacheTTL     time.Duration
}

func NewRoot(version, commit, date string) *cobra.Command {
	opts := &options{toolVersion: version + "@" + commit}

	root := &cobra.Command{
		Use:           "securock",
		Short:         "Security analysis for dependencies, source code, secrets, and infrastructure",
		Long:          "Securock combines dependency trust, source code analysis, secret detection, and infrastructure checks. Run security for a unified report, or lock and verify to track dependency trust drift.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       formatVersion(version, commit, date),
		// Set on every run, so a flag from one run never leaks into the next.
		PersistentPreRunE: func(*cobra.Command, []string) error {
			if opts.cacheTTL < 0 {
				return opErr(fmt.Errorf("--cache-ttl must be positive: %s", opts.cacheTTL))
			}
			httpx.Configure(opts.noCache, opts.cacheTTL)
			return nil
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")

	root.PersistentFlags().BoolVar(&opts.offline, "offline", false, "skip remote lookups")
	root.PersistentFlags().StringVar(&opts.network, "network", "", "network mode: public-only, offline, or allow-all")
	root.PersistentFlags().StringVar(&opts.format, "format", "text", "output format: text, json, sarif (code scanning), junit (JUnit XML), or markdown (PR comment); graph also takes mermaid and dot")
	root.PersistentFlags().StringVar(&opts.lockPath, "lock", "", "path to securock.lock")
	root.PersistentFlags().StringVar(&opts.policy, "policy", "", "path to a policy file")
	root.PersistentFlags().StringVar(&opts.profile, "profile", "", "built-in policy profile: default or strict")
	root.PersistentFlags().StringVar(&opts.output, "output", "", "write the report to this file instead of stdout")
	root.PersistentFlags().StringVar(&opts.exceptions, "exceptions", "", "path to the accepted-findings file (default .securock/exceptions.yaml in the project)")
	root.PersistentFlags().BoolVar(&opts.reachability, "reachability", false, "record package scope and dependencies, and mark each vulnerability reachable, unreachable, or unknown")
	root.PersistentFlags().BoolVar(&opts.noCache, "no-cache", false, "do not read or write the on-disk cache of registry and OSV responses")
	root.PersistentFlags().DurationVar(&opts.cacheTTL, "cache-ttl", 0, "how long a cached response is used, such as 10m or 24h (default 1h)")
	root.PersistentFlags().BoolVar(&opts.noFail, "no-fail", false, "do not fail on findings or trust violations; operational errors still fail")

	root.AddCommand(newScanCommand(opts))
	root.AddCommand(newInitCommand(opts))
	root.AddCommand(newLockCommand(opts))
	root.AddCommand(newDiffCommand(opts))
	root.AddCommand(newUpdateCommand(opts))
	root.AddCommand(newVerifyCommand(opts))
	root.AddCommand(newExplainCommand(opts))
	root.AddCommand(newGraphCommand(opts))
	root.AddCommand(newAuditCommand(opts))
	root.AddCommand(newSecurityCommand(opts))
	root.AddCommand(newDASTCommand(opts))
	root.AddCommand(newAuthorizationCommand(opts))
	root.AddCommand(newCSPMCommand(opts))
	root.AddCommand(newBaselineCommand(opts))
	root.AddCommand(newContainerCommand(opts))
	root.AddCommand(newRemediateCommand(opts))
	root.AddCommand(newWatchCommand(opts))
	root.AddCommand(newTriageCommand(opts))
	root.AddCommand(newPrioritizeCommand(opts))
	root.AddCommand(newEnforceCommand(opts))
	root.AddCommand(newIntegrationCommand(opts))
	root.AddCommand(newHistoryCommand(opts))
	root.AddCommand(newDashboardCommand(opts))
	root.AddCommand(newInventoryCommand(opts))
	root.AddCommand(newIdentityCommand(opts))
	root.AddCommand(newServeCommand(opts))
	root.AddCommand(newControlCommand(opts))
	root.AddCommand(newRunnerCommand(opts))
	root.AddCommand(newEvidenceCommand(opts))
	root.AddCommand(newSASTCommand(opts))
	root.AddCommand(newChainCommand(opts))
	root.AddCommand(newImportCommand(opts))
	root.AddCommand(newDoctorCommand(opts))
	root.AddCommand(newSBOMCommand(opts))
	root.AddCommand(newAcceptCommand(opts))
	root.AddCommand(newVEXCommand(opts))
	root.AddCommand(newCacheCommand())
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), formatVersion(version, commit, date))
		},
	})

	root.RunE = newScanCommand(opts).RunE
	withRecursive(opts, root)
	redirectOutput(opts, root)

	return root
}

func Execute(version, commit, date string) {
	if err := NewRoot(version, commit, date).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var e exitError
		if asExit(err, &e) {
			os.Exit(e.code)
		}
		os.Exit(exitFail)
	}
}

func formatVersion(version, commit, date string) string {
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "none"
	}
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}

func scanOptions(opts *options, pol policy.Document) (policy.Network, error) {
	net := pol.Network
	if opts.network != "" {
		mode := policy.Mode(opts.network)
		if !policy.ValidMode(mode) || mode == "" {
			return policy.Network{}, opErr(fmt.Errorf("unknown network mode %q", opts.network))
		}
		net.Mode = mode
	}
	if opts.offline {
		net.Mode = policy.ModeOffline
	}
	return net, nil
}

func projectPath(args []string) string {
	if len(args) == 0 {
		return "."
	}
	return args[0]
}

// redirectOutput makes every command honor --output. The report is buffered so the file
// is written even when the command exits 1 for a trust violation, which is when a SARIF
// report matters most. Nothing is written if the command produced no output.
func redirectOutput(opts *options, root *cobra.Command) {
	wrap := func(cmd *cobra.Command) {
		run := cmd.RunE
		if run == nil {
			return
		}
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			if opts.output == "" {
				return run(cmd, args)
			}
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			err := run(cmd, args)
			if buf.Len() > 0 {
				if werr := os.WriteFile(opts.output, buf.Bytes(), 0o644); werr != nil {
					return opErr(werr)
				}
			}
			return err
		}
	}
	wrap(root)
	for _, cmd := range root.Commands() {
		wrap(cmd)
	}
}

// reportLocation is the file SARIF results point at: the project's lockfile, relative to
// the working directory so code scanning can map it onto the repository.
func reportLocation(path, lockOverride string) string {
	loc := lock.Path(path, lockOverride)
	if !filepath.IsAbs(loc) {
		return filepath.ToSlash(filepath.Clean(loc))
	}
	if cwd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(cwd, loc); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(loc)
}
