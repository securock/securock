package sbom_test

import (
	"testing"

	"github.com/securock/securock/internal/sbom"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"a","version":"1","purl":"pkg:npm/a@1"}]}`))
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","annotations":[{"comment":"securock:digest=x"}]}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = sbom.Parse(raw)
	})
}
