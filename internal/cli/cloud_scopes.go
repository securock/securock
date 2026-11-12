package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/securock/securock/internal/cspm"
	"github.com/securock/securock/internal/finding"
	p "github.com/securock/securock/pkg/policy"
	"github.com/spf13/cobra"
	"strings"
)

type cloudScopes struct{ aws, azure, gcp []string }

func (s *cloudScopes) count() int { return len(s.aws) + len(s.azure) + len(s.gcp) }
func (s *cloudScopes) bind(c *cobra.Command) {
	c.Flags().StringArrayVar(&s.aws, "aws-scope", nil, "additional AWS profile@region (repeatable)")
	c.Flags().StringArrayVar(&s.azure, "azure-subscription", nil, "Azure subscription for read-only Resource Graph collection (repeatable)")
	c.Flags().StringArrayVar(&s.gcp, "gcp-project", nil, "GCP project for read-only Cloud Asset collection (repeatable)")
}
func (s *cloudScopes) validate(net p.Network) error {
	if s.count() > 0 && net.ResolvedMode() != p.ModeAllowAll {
		return fmt.Errorf("cloud collection requires --network allow-all")
	}
	for _, scope := range s.aws {
		profile, region, ok := strings.Cut(scope, "@")
		if !ok {
			return fmt.Errorf("AWS scope must be profile@region")
		}
		if _, e := cspm.AWSCommand(region, profile); e != nil {
			return e
		}
	}
	return nil
}
func (s *cloudScopes) scan(ctx context.Context) ([]finding.Finding, error) {
	var out []finding.Finding
	var failures []error
	consume := func(raw []byte, e error, scope string) {
		if e == nil {
			r, err := cspm.Read(bytes.NewReader(raw))
			out = append(out, r.Findings...)
			e = err
		}
		if e != nil {
			failures = append(failures, e)
			out = append(out, finding.Finding{ID: "cspm:analysis-incomplete", Severity: finding.SeverityHigh, Title: "Cloud scope collection did not complete", Subject: scope})
		}
	}
	for _, scope := range s.aws {
		profile, region, _ := strings.Cut(scope, "@")
		raw, e := cspm.CollectAWS(ctx, region, profile)
		consume(raw, e, scope)
	}
	for _, scope := range s.azure {
		raw, e := cspm.CollectOther(ctx, "azure", scope)
		consume(raw, e, scope)
	}
	for _, scope := range s.gcp {
		raw, e := cspm.CollectOther(ctx, "gcp", scope)
		consume(raw, e, scope)
	}
	return out, errors.Join(failures...)
}
