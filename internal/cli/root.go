package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type options struct {
	offline  bool
	format   string
	lockPath string
	policy   string
	noFail   bool
}

func NewRoot(version, commit, date string) *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:           "securock",
		Short:         "Supply-chain trust layer for software dependencies",
		Long:          "Securock scans language lockfiles, evaluates trust, and writes a language-agnostic securock.lock.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       formatVersion(version, commit, date),
	}
	root.SetVersionTemplate("{{.Version}}\n")

	root.PersistentFlags().BoolVar(&opts.offline, "offline", false, "skip remote vulnerability lookups")
	root.PersistentFlags().StringVar(&opts.format, "format", "text", "output format: text or json")
	root.PersistentFlags().StringVar(&opts.lockPath, "lock", "", "path to securock.lock")
	root.PersistentFlags().StringVar(&opts.policy, "policy", "", "path to a policy file")
	root.PersistentFlags().BoolVar(&opts.noFail, "no-fail", false, "always exit 0")

	root.AddCommand(newScanCommand(opts))
	root.AddCommand(newLockCommand(opts))
	root.AddCommand(newDiffCommand(opts))
	root.AddCommand(newVerifyCommand(opts))
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), formatVersion(version, commit, date))
		},
	})

	root.RunE = newScanCommand(opts).RunE

	return root
}

func Execute(version, commit, date string) {
	if err := NewRoot(version, commit, date).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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

func projectPath(args []string) string {
	if len(args) == 0 {
		return "."
	}
	return args[0]
}
