package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/inventory"
	"github.com/securock/securock/internal/release"
	"github.com/spf13/cobra"
	"os"
)

func newReleaseCommand(opts *options) *cobra.Command {
	var bomFile, seedEnv, public, catalogFile, customer, advisories, inventoryFile string
	c := &cobra.Command{Use: "release ACTION FILE.json", Short: "Sign releases, register deliveries, query customer impact or verify deployment drift", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, a []string) error {
		read := func(path string, v any) error {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if len(raw) > 32<<20 {
				return fmt.Errorf("input exceeds limit")
			}
			return json.Unmarshal(raw, v)
		}
		var bom []byte
		var e error
		if bomFile != "" {
			bom, e = os.ReadFile(bomFile)
			if e != nil {
				return opErr(e)
			}
		}
		key, e := base64.StdEncoding.DecodeString(public)
		if a[0] != "sign" && (e != nil || len(key) != 32) {
			return opErr(fmt.Errorf("trusted public key required"))
		}
		var result any
		switch a[0] {
		case "sign":
			var statement release.Statement
			if e = read(a[1], &statement); e != nil {
				return opErr(e)
			}
			seed, e := base64.StdEncoding.DecodeString(os.Getenv(seedEnv))
			if e != nil {
				return opErr(e)
			}
			result, e = release.Sign(statement, bom, seed)
			if e != nil {
				return opErr(e)
			}
		case "verify", "register":
			var envelope release.Envelope
			if e = read(a[1], &envelope); e != nil {
				return opErr(e)
			}
			statement, e := release.Verify(envelope, bom, ed25519.PublicKey(key))
			if e != nil {
				return opErr(e)
			}
			if a[0] == "register" {
				if catalogFile == "" {
					return opErr(fmt.Errorf("catalog required"))
				}
				if e = release.Register(catalogFile, release.Shipment{Customer: customer, Attestation: envelope, SBOM: bom}, ed25519.PublicKey(key)); e != nil {
					return opErr(e)
				}
			}
			result = statement
		case "impact", "link", "drift":
			var catalog release.Catalog
			if e = read(a[1], &catalog); e != nil {
				return opErr(e)
			}
			if a[0] == "impact" {
				var aa []release.Advisory
				if e = read(advisories, &aa); e != nil {
					return opErr(e)
				}
				result, e = release.Impacts(catalog, aa, ed25519.PublicKey(key))
				if e != nil {
					return opErr(e)
				}
			} else {
				var r inventory.Report
				if e = read(inventoryFile, &r); e != nil {
					return opErr(e)
				}
				graph, report, e := release.Link(catalog, r, ed25519.PublicKey(key))
				if e != nil {
					return opErr(e)
				}
				if a[0] == "link" {
					result = graph
				} else {
					if e = finding.Write(c.OutOrStdout(), report, opts.format); e != nil {
						return opErr(e)
					}
					if !opts.noFail && report.AtLeast(finding.SeverityHigh) > 0 {
						return trustErr("deployment identity missing or unapproved")
					}
					return nil
				}
			}
		default:
			return opErr(fmt.Errorf("action must be sign, verify, register, impact, link or drift"))
		}
		return opErr(json.NewEncoder(c.OutOrStdout()).Encode(result))
	}}
	c.Flags().StringVar(&bomFile, "sbom", "", "exact CycloneDX/SPDX JSON bytes")
	c.Flags().StringVar(&seedEnv, "seed-env", "SECUROCK_RELEASE_SEED", "base64 Ed25519 signing seed environment variable")
	c.Flags().StringVar(&public, "public-key", "", "independently trusted base64 public key")
	c.Flags().StringVar(&catalogFile, "catalog", "", "private delivery catalog to update")
	c.Flags().StringVar(&customer, "customer", "", "local customer identifier")
	c.Flags().StringVar(&advisories, "advisories", "", "exact versioned purl advisory mapping JSON")
	c.Flags().StringVar(&inventoryFile, "inventory", "", "observed inventory report JSON")
	return c
}
