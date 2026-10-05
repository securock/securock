package osv_test

import (
	"testing"

	"github.com/securock/securock/internal/osv"
	"github.com/securock/securock/pkg/lockfile"
)

func TestPartitionMaliciousIDs(t *testing.T) {
	vulns, mal := osv.Partition([]lockfile.Vulnerability{
		{ID: "GHSA-aaaa-bbbb-cccc"},
		{ID: "MAL-2026-2307"},
		{ID: "CVE-2024-1234"},
		{ID: "mal-2024-1"},
	})
	if len(vulns) != 2 || vulns[0].ID != "GHSA-aaaa-bbbb-cccc" || vulns[1].ID != "CVE-2024-1234" {
		t.Fatalf("vulns = %#v", vulns)
	}
	if len(mal) != 2 || mal[0].ID != "MAL-2026-2307" || mal[1].ID != "mal-2024-1" {
		t.Fatalf("malicious = %#v", mal)
	}
}
