package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/lock"
	"github.com/securock/securock/internal/sbom"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/spf13/cobra"
)

// maxSBOMBytes bounds the SBOM verify reads; real documents are far smaller.
const maxSBOMBytes = 64 << 20

func newSBOMCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Export or verify a software bill of materials",
	}
	cmd.AddCommand(newSBOMExportCommand(opts), newSBOMVerifyCommand(opts))
	return cmd
}

func newSBOMExportCommand(opts *options) *cobra.Command {
	var spec string
	cmd := &cobra.Command{
		Use:   "export [path]",
		Short: "Write securock.lock as a CycloneDX or SPDX SBOM",
		Long: "Write securock.lock as a CycloneDX 1.6 or SPDX 2.3 JSON SBOM on stdout.\n" +
			"Trust evidence is carried as securock:* properties (CycloneDX) or annotations (SPDX).\n" +
			"The output is deterministic. Set SOURCE_DATE_EPOCH to stamp a creation time.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			write, err := sbomWriter(spec)
			if err != nil {
				return opErr(err)
			}
			doc, err := readLock(cmd, projectPath(args), opts)
			if err != nil {
				return err
			}
			o := sbom.Options{
				ToolVersion: toolVersion(cmd),
				Created:     sbom.CreatedFromEnv(os.Getenv),
			}
			if err := write(cmd.OutOrStdout(), doc, o); err != nil {
				return opErr(err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&spec, "spec", sbom.SpecCycloneDX, "SBOM format: cyclonedx or spdx")
	return cmd
}

func newSBOMVerifyCommand(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "verify <sbom> [path]",
		Short: "Check a CycloneDX or SPDX SBOM against securock.lock",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := readSBOM(args[0])
			if err != nil {
				return opErr(err)
			}
			doc, err := sbom.Parse(raw)
			if err != nil {
				return opErr(fmt.Errorf("%s: %w", args[0], err))
			}
			locked, err := readLock(cmd, projectPath(args[1:]), opts)
			if err != nil {
				return err
			}

			report := sbom.Verify(locked, doc)
			if err := finding.Write(cmd.OutOrStdout(), report, opts.format); err != nil {
				return opErr(err)
			}
			if opts.noFail || len(report.Findings) == 0 {
				return nil
			}
			return trustErr("sbom differs from the lockfile: %d findings", len(report.Findings))
		},
	}
}

type sbomWrite func(io.Writer, lockfile.Document, sbom.Options) error

func sbomWriter(spec string) (sbomWrite, error) {
	switch strings.ToLower(spec) {
	case sbom.SpecCycloneDX:
		return sbom.WriteCycloneDX, nil
	case sbom.SpecSPDX:
		return sbom.WriteSPDX, nil
	default:
		return nil, fmt.Errorf("unknown SBOM spec %q: use cyclonedx or spdx", spec)
	}
}

func readLock(cmd *cobra.Command, path string, opts *options) (lockfile.Document, error) {
	doc, migrated, err := lock.Read(lock.Path(path, opts.lockPath))
	if err != nil {
		return lockfile.Document{}, opErr(err)
	}
	if migrated {
		fmt.Fprintln(cmd.ErrOrStderr(), lock.MigrationWarning)
	}
	return doc, nil
}

func readSBOM(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSBOMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSBOMBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxSBOMBytes)
	}
	return raw, nil
}

// toolVersion is the bare version from "dev (commit none, built unknown)".
func toolVersion(cmd *cobra.Command) string {
	fields := strings.Fields(cmd.Root().Version)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
