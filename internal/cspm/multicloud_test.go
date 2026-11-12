package cspm_test

import (
	"github.com/securock/securock/internal/cspm"
	"testing"
)

func TestAzureAndGCPExports(t *testing.T) {
	for _, raw := range []string{`{"data":[{"id":"/subscriptions/x/storage","type":"Microsoft.Storage/storageAccounts","properties":{"allowBlobPublicAccess":true,"supportsHttpsTrafficOnly":false}}]}`, `[{"name":"//compute/x","assetType":"compute.googleapis.com/Firewall","resource":{"data":{"disabled":false,"direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"all"}]}}}]`} {
		r, ok, e := cspm.OtherCloud([]byte(raw))
		if e != nil || !ok || len(r.Findings) < 2 {
			t.Fatal(r, ok, e)
		}
	}
	if _, _, e := cspm.OtherCloud([]byte(`{"data":[],"$skipToken":"more"}`)); e == nil {
		t.Fatal("partial page accepted")
	}
}

func TestMissingFirewallSourcesStayUnknown(t *testing.T) {
	r, _, e := cspm.OtherCloud([]byte(`[{"name":"firewall","assetType":"compute.googleapis.com/Firewall","resource":{"data":{"disabled":false,"direction":"INGRESS","allowed":[{"IPProtocol":"all"}]}}}]`))
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "cspm:gcp-check-unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing sources treated as private")
	}
}
