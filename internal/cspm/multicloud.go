package cspm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/external"
	"github.com/securock/securock/internal/finding"
	"regexp"
	"strings"
)

// OtherCloud reads native Azure Resource Graph or GCP Cloud Asset resource exports.
func OtherCloud(raw []byte) (finding.Report, bool, error) {
	var azure struct {
		Data []struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Properties fields `json:"properties"`
		} `json:"data"`
		Skip    string `json:"$skipToken"`
		SkipCLI string `json:"skip_token"`
	}
	if json.Unmarshal(raw, &azure) == nil && azure.Data != nil {
		if azure.Skip != "" || azure.SkipCLI != "" {
			return finding.New("cspm", nil), true, fmt.Errorf("Azure inventory has uncollected pages")
		}
		var out []finding.Finding
		for _, r := range azure.Data {
			add := func(id string, sev finding.Severity, title, detail, fix string) {
				out = append(out, finding.Finding{ID: "cspm:azure-" + id, Severity: sev, Title: title, Detail: detail, Remediation: fix, Subject: r.ID})
			}
			if r.ID == "" || r.Type == "" {
				return finding.New("cspm", out), true, fmt.Errorf("Azure resource identity missing")
			}
			switch strings.ToLower(r.Type) {
			case "microsoft.storage/storageaccounts":
				boolRule(r.Properties, "allowBlobPublicAccess", "public-blob", "Azure storage permits public blob access", "Disable public blob access unless intentional.", true, finding.SeverityMedium, add)
				boolRule(r.Properties, "supportsHttpsTrafficOnly", "http-storage", "Azure storage permits unencrypted traffic", "Require HTTPS traffic.", false, finding.SeverityHigh, add)
			case "microsoft.network/networksecuritygroups":
				rules, ok := r.Properties.array("securityRules")
				if !ok {
					unknown(add, "securityRules")
				}
				for _, rule := range rules {
					p, ok := object(rule.get("properties"))
					if !ok {
						unknown(add, "rule properties")
						continue
					}
					source := p.text("sourceAddressPrefix")
					port := p.text("destinationPortRange")
					if strings.EqualFold(p.text("access"), "Allow") && strings.EqualFold(p.text("direction"), "Inbound") && (source == "*" || source == "Internet" || source == "0.0.0.0/0" || source == "::/0") && (port == "*" || port == "22" || port == "3389") {
						add("open-admin", finding.SeverityHigh, "Azure rule permits public administrative ingress", "Review effective network access and other controls.", "Restrict source ranges and administrative ports.")
					}
				}
			default:
				unknown(add, "unsupported Azure resource type")
			}
		}
		out = append(out, cloudScope("azure"))
		if len(azure.Data) == 0 {
			return finding.New("cspm", out), true, fmt.Errorf("no Azure resources returned")
		}
		return finding.New("cspm", out), true, nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		var assets []struct {
			Name     string `json:"name"`
			Type     string `json:"assetType"`
			Resource struct {
				Data fields `json:"data"`
			} `json:"resource"`
		}
		if json.Unmarshal(raw, &assets) != nil {
			return finding.New("cspm", nil), true, fmt.Errorf("invalid GCP asset array")
		}
		var out []finding.Finding
		for _, r := range assets {
			if r.Name == "" || r.Type == "" {
				return finding.New("cspm", out), true, fmt.Errorf("GCP asset identity missing")
			}
			add := func(id string, sev finding.Severity, title, detail, fix string) {
				out = append(out, finding.Finding{ID: "cspm:gcp-" + id, Severity: sev, Title: title, Detail: detail, Remediation: fix, Subject: r.Name})
			}
			switch r.Type {
			case "compute.googleapis.com/Firewall":
				disabled, ok := r.Resource.Data.boolean("disabled")
				if !ok {
					unknown(add, "firewall disabled state")
					continue
				}
				if disabled || r.Resource.Data.text("direction") != "INGRESS" {
					continue
				}
				sources := stringsOf(r.Resource.Data.get("sourceRanges"))
				if len(sources) == 0 {
					unknown(add, "firewall source ranges")
					continue
				}
				public := false
				for _, s := range sources {
					if s == "0.0.0.0/0" || s == "::/0" {
						public = true
					}
				}
				if !public {
					continue
				}
				allowed, ok := r.Resource.Data.array("allowed")
				if !ok {
					unknown(add, "allowed firewall traffic")
					continue
				}
				for _, a := range allowed {
					protocol := a.text("IPProtocol")
					ports := stringsOf(a.get("ports"))
					if protocol == "all" || ((protocol == "tcp" || protocol == "udp") && len(ports) == 0) {
						add("open-admin", finding.SeverityHigh, "GCP firewall permits all ports from the internet", "", "Restrict source ranges and allowed ports.")
					}
					for _, port := range ports {
						if port == "22" || port == "3389" {
							add("open-admin", finding.SeverityHigh, "GCP firewall permits public administrative ingress", "", "Restrict administrative access.")
						}
					}
				}
			case "storage.googleapis.com/Bucket":
				iam, ok := object(r.Resource.Data.get("iamConfiguration"))
				if !ok {
					unknown(add, "bucket IAM configuration")
					continue
				}
				uniform, ok := object(iam.get("uniformBucketLevelAccess"))
				if !ok {
					unknown(add, "uniformBucketLevelAccess")
				} else {
					boolRule(uniform, "enabled", "bucket-acls", "GCP bucket uses legacy ACL access", "Review ACLs and enable uniform bucket-level access.", false, finding.SeverityMedium, add)
				}
				if iam.text("publicAccessPrevention") != "enforced" {
					unknown(add, "effective bucket public access prevention")
				}
			default:
				unknown(add, "unsupported GCP asset type")
			}
		}
		out = append(out, cloudScope("gcp"))
		if len(assets) == 0 {
			return finding.New("cspm", out), true, fmt.Errorf("no GCP assets returned")
		}
		return finding.New("cspm", out), true, nil
	}
	return finding.Report{}, false, nil
}
func cloudScope(provider string) finding.Finding {
	return finding.Finding{ID: "cspm:snapshot-scope", Severity: finding.SeverityInfo, Title: "Cloud snapshot is scoped recorded evidence", Subject: provider, Detail: "Freshness, complete account coverage, effective permissions and network reachability are not established."}
}
func CollectOther(ctx context.Context, provider, scope string) ([]byte, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(scope) {
		return nil, fmt.Errorf("invalid cloud scope identifier")
	}
	switch provider {
	case "azure":
		return external.Run(ctx, "az", "graph", "query", "--subscriptions", scope, "--graph-query", "Resources | where type in~ ('microsoft.storage/storageaccounts','microsoft.network/networksecuritygroups') | project id,type,properties", "--first", "1000", "--output", "json")
	case "gcp":
		return external.Run(ctx, "gcloud", "asset", "list", "--project", scope, "--content-type", "resource", "--asset-types", "compute.googleapis.com/Firewall,storage.googleapis.com/Bucket", "--format", "json", "--quiet")
	}
	return nil, fmt.Errorf("unsupported cloud provider")
}
