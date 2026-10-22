package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/securock/securock/internal/exceptions"
	"github.com/securock/securock/internal/sbom"
	"github.com/securock/securock/internal/vex"
	pkgexceptions "github.com/securock/securock/pkg/exceptions"
	"github.com/securock/securock/pkg/lockfile"
	"github.com/spf13/cobra"
)

func newVEXCommand(opts *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vex",
		Short: "Export accepted vulnerabilities as a VEX document",
	}
	cmd.AddCommand(newVEXExportCommand(opts))
	return cmd
}

type vexWrite func(io.Writer, lockfile.Document, pkgexceptions.Document, vex.Options) error

func newVEXExportCommand(opts *options) *cobra.Command {
	var spec, author string
	cmd := &cobra.Command{
		Use:   "export [path]",
		Short: "Write accepted vulnerabilities as OpenVEX or CycloneDX VEX",
		Long: "Write the vulnerabilities recorded with securock accept as a VEX document on stdout.\n" +
			"An exception with --justification becomes not_affected; any other becomes affected with\n" +
			"the acceptance as its action statement. Expired exceptions and exceptions for packages\n" +
			"that are not in securock.lock are left out. Set SOURCE_DATE_EPOCH to fix the timestamp.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var write vexWrite
			switch strings.ToLower(spec) {
			case vex.SpecOpenVEX:
				write = vex.WriteOpenVEX
			case vex.SpecCycloneDX:
				write = vex.WriteCycloneDX
			default:
				return opErr(fmt.Errorf("unknown VEX spec %q: use openvex or cyclonedx", spec))
			}
			if strings.TrimSpace(author) == "" {
				return opErr(fmt.Errorf("--author is required: a VEX document says who vouches for it"))
			}

			path := projectPath(args)
			lock, err := readLock(cmd, path, opts)
			if err != nil {
				return err
			}
			accepted, err := exceptions.Load(exceptions.Path(path, opts.exceptions))
			if err != nil {
				return opErr(err)
			}

			stamp := sbom.CreatedFromEnv(os.Getenv)
			if stamp.IsZero() {
				stamp = time.Now()
			}
			o := vex.Options{Author: author, Time: stamp, ToolVersion: toolVersion(cmd)}
			if err := write(cmd.OutOrStdout(), lock, accepted, o); err != nil {
				return opErr(err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&spec, "spec", vex.SpecOpenVEX, "VEX format: openvex or cyclonedx")
	cmd.Flags().StringVar(&author, "author", "", "who vouches for the document, such as a team or person (required)")
	return cmd
}
