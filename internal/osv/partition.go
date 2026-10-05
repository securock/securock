package osv

import (
	"strings"

	"github.com/securock/securock/pkg/lockfile"
)

// Partition separates OSV hit IDs into vulnerabilities and malicious
// package reports. OpenSSF Malicious Packages uses the MAL- prefix.
func Partition(hits []lockfile.Vulnerability) (vulns []lockfile.Vulnerability, malicious []lockfile.MaliciousReport) {
	for _, hit := range hits {
		if hit.ID == "" {
			continue
		}
		if IsMaliciousID(hit.ID) {
			malicious = append(malicious, lockfile.MaliciousReport{ID: hit.ID})
			continue
		}
		vulns = append(vulns, hit)
	}
	return vulns, malicious
}

func IsMaliciousID(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "MAL-")
}
