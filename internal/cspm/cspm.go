// Package cspm evaluates recorded AWS configuration without modifying cloud resources.
package cspm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/securock/securock/internal/finding"
)

const MaxInventoryBytes = 16 << 20

var ResourceTypes = []string{"AWS::CloudTrail::Trail", "AWS::EC2::SecurityGroup", "AWS::IAM::Policy", "AWS::IAM::Role", "AWS::RDS::DBInstance", "AWS::S3::Bucket"}

type resource struct {
	Type          string                     `json:"resourceType"`
	ID            string                     `json:"resourceId"`
	Account       string                     `json:"accountId"`
	Region        string                     `json:"awsRegion"`
	Status        string                     `json:"configurationItemStatus"`
	Configuration json.RawMessage            `json:"configuration"`
	Supplementary map[string]json.RawMessage `json:"supplementaryConfiguration"`
}

// Read accepts AWS Config snapshots and select-resource-config CLI results.
// Resource contents are never copied into reports, since they can contain secrets.
func Read(r io.Reader) (finding.Report, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxInventoryBytes+1))
	if err != nil {
		return finding.New("cspm", nil), fmt.Errorf("cannot read AWS Config inventory")
	}
	if len(raw) > MaxInventoryBytes {
		return finding.New("cspm", nil), fmt.Errorf("AWS Config inventory exceeds %d bytes", MaxInventoryBytes)
	}
	if report, ok, err := OtherCloud(raw); ok {
		return report, err
	}
	var envelope struct {
		Items     json.RawMessage `json:"configurationItems"`
		Results   json.RawMessage `json:"Results"`
		NextToken string          `json:"NextToken"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return finding.New("cspm", nil), fmt.Errorf("invalid AWS Config inventory JSON")
	}
	if envelope.NextToken != "" {
		return finding.New("cspm", nil), fmt.Errorf("AWS Config inventory is paginated; collect all pages before scanning")
	}
	var items []json.RawMessage
	switch {
	case len(envelope.Items) > 0 && len(envelope.Results) > 0:
		return finding.New("cspm", nil), fmt.Errorf("inventory must contain either configurationItems or Results")
	case len(envelope.Items) > 0:
		err = json.Unmarshal(envelope.Items, &items)
	case len(envelope.Results) > 0:
		var results []string
		err = json.Unmarshal(envelope.Results, &results)
		for _, s := range results {
			items = append(items, json.RawMessage(s))
		}
	default:
		return finding.New("cspm", nil), fmt.Errorf("expected AWS Config configurationItems or Results")
	}
	if err != nil {
		return finding.New("cspm", nil), fmt.Errorf("invalid AWS Config resource collection")
	}
	var found []finding.Finding
	covered := map[string]bool{}
	seen := map[string]bool{}
	incomplete := false
	add := func(id string, sev finding.Severity, subject, title, detail, fix string) {
		found = append(found, finding.Finding{ID: "cspm:" + id, Severity: sev, Subject: subject, Title: title, Detail: detail, Remediation: fix})
	}
	for _, raw := range items {
		var res resource
		if json.Unmarshal(raw, &res) != nil || res.Type == "" || res.ID == "" {
			return finding.New("cspm", found), fmt.Errorf("invalid AWS Config resource identity")
		}
		if res.Status == "ResourceDeleted" || res.Status == "ResourceDeletedNotRecorded" {
			continue
		}
		subject := strings.Join([]string{res.Type, res.Account, res.Region, res.ID}, "/")
		if seen[subject] {
			return finding.New("cspm", found), fmt.Errorf("duplicate AWS Config resource identity; use one current snapshot per resource")
		}
		seen[subject] = true
		if !slices.Contains(ResourceTypes, res.Type) {
			add("unsupported-resource", finding.SeverityInfo, subject, "Resource type has no CSPM checks", "", "Use provider-specific checks for this resource type.")
			continue
		}
		config, ok := object(res.Configuration)
		if !ok || len(config) == 0 || (res.Status != "" && res.Status != "OK" && res.Status != "ResourceDiscovered") {
			add("analysis-incomplete", finding.SeverityHigh, subject, "Resource configuration is unavailable or invalid", "", "Collect a current configuration for this resource and rerun CSPM.")
			incomplete = true
			continue
		}
		if res.Account == "" || res.Region == "" {
			add("scope-unavailable", finding.SeverityInfo, subject, "Account or region metadata is missing", "Resource identity and account coverage are incomplete.", "Include accountId and awsRegion in the inventory.")
		}
		covered[res.Type] = true
		check(res, config, func(id string, sev finding.Severity, title, detail, fix string) {
			add(id, sev, subject, title, detail, fix)
		})
	}
	for _, typ := range ResourceTypes {
		if !covered[typ] {
			add("coverage-unavailable", finding.SeverityInfo, typ, "No evaluable resources of this type in the inventory", "Absence from this snapshot does not establish absence from the account.", "Check AWS Config recorder coverage, region, permissions, and snapshot freshness.")
		}
	}
	// Offline exports are point-in-time evidence, not a statement about current cloud state.
	add("snapshot-scope", finding.SeverityInfo, "aws-config", "CSPM covers recorded configuration only", "Freshness, account-wide coverage, effective IAM permissions, network reachability, and compliance certification are not established.", "Use a current complete AWS Config inventory and review each reported resource.")
	report := finding.New("cspm", unique(found))
	if incomplete || len(covered) == 0 {
		return report, fmt.Errorf("CSPM analysis incomplete: no usable configuration for one or more recorded resources")
	}
	return report, nil
}

type emit func(string, finding.Severity, string, string, string)
type fields map[string]json.RawMessage

func object(raw json.RawMessage) (fields, bool) {
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		raw = []byte(encoded)
	}
	var out fields
	err := json.Unmarshal(raw, &out)
	return out, err == nil && out != nil
}
func (f fields) get(key string) json.RawMessage {
	for k, v := range f {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}
func (f fields) boolean(key string) (bool, bool) {
	raw := f.get(key)
	var b bool
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}
func (f fields) text(key string) string { var s string; json.Unmarshal(f.get(key), &s); return s }
func (f fields) array(key string) ([]fields, bool) {
	var a []fields
	raw := f.get(key)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &a) != nil {
		return nil, false
	}
	return a, true
}
func stringsOf(raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var ss []string
	json.Unmarshal(raw, &ss)
	return ss
}
func unknown(add emit, rule string) {
	add("check-unavailable", finding.SeverityInfo, "Cloud setting was not evaluated", rule, "Collect the missing setting in AWS Config; an omitted value is unknown, not secure.")
}
func boolRule(c fields, key, id, title, fix string, unsafe bool, sev finding.Severity, add emit) {
	value, ok := c.boolean(key)
	if !ok {
		unknown(add, key)
		return
	}
	if value == unsafe {
		add(id, sev, title, "", fix)
	}
}

func check(res resource, c fields, add emit) {
	switch res.Type {
	case "AWS::EC2::SecurityGroup":
		securityGroup(c, add)
	case "AWS::RDS::DBInstance":
		boolRule(c, "publiclyAccessible", "rds-public", "Database is configured with public accessibility", "Disable public accessibility and review network access controls.", true, finding.SeverityHigh, add)
		boolRule(c, "storageEncrypted", "rds-unencrypted", "Database storage encryption is disabled", "Migrate to an encrypted database using the provider-supported process.", false, finding.SeverityHigh, add)
		days, ok := c.integer("backupRetentionPeriod")
		if !ok || days < 0 {
			unknown(add, "backupRetentionPeriod")
		} else if days == 0 {
			add("rds-backups-disabled", finding.SeverityMedium, "Automated database backups are disabled", "", "Set a backup retention period that meets recovery requirements.")
		}
	case "AWS::CloudTrail::Trail":
		boolRule(c, "isMultiRegionTrail", "cloudtrail-single-region", "CloudTrail trail covers a single region", "Review account-wide trail coverage and enable a multi-region trail where required.", false, finding.SeverityMedium, add)
		boolRule(c, "logFileValidationEnabled", "cloudtrail-validation-disabled", "CloudTrail log file validation is disabled", "Enable CloudTrail log file validation.", false, finding.SeverityMedium, add)
	case "AWS::S3::Bucket":
		bucket(res, c, add)
	case "AWS::IAM::Policy":
		if doc := c.get("policyDocument"); len(doc) > 0 {
			iam(doc, false, add)
			return
		}
		versions, ok := c.array("policyVersionList")
		if ok {
			for _, v := range versions {
				if b, ok := v.boolean("isDefaultVersion"); ok && b {
					iam(v.get("document"), false, add)
					return
				}
			}
		}
		unknown(add, "IAM default policy document")
	case "AWS::IAM::Role":
		iam(c.get("assumeRolePolicyDocument"), true, add)
		policies, ok := c.array("rolePolicyList")
		if !ok {
			unknown(add, "rolePolicyList")
		} else {
			for _, p := range policies {
				iam(p.get("policyDocument"), false, add)
			}
		}
	}
}

func securityGroup(c fields, add emit) {
	permissions, ok := c.array("ipPermissions")
	if !ok {
		unknown(add, "ipPermissions")
		return
	}
	for _, p := range permissions {
		public := false
		ranges, ok4 := cidrs(p.get("ipRanges"), "cidrIp")
		v6, ok6 := cidrs(p.get("ipv6Ranges"), "cidrIpv6")
		public = slices.Contains(ranges, "0.0.0.0/0") || slices.Contains(v6, "::/0")
		if (!ok4 && len(p.get("ipRanges")) > 0) || (!ok6 && len(p.get("ipv6Ranges")) > 0) || (!ok4 && !ok6) {
			unknown(add, "ingress CIDR ranges")
		}
		if !public {
			continue
		}
		protocol := p.text("ipProtocol")
		if protocol == "" {
			unknown(add, "ingress protocol")
			continue
		}
		if protocol == "-1" {
			add("security-group-open-admin", finding.SeverityHigh, "Security group permits all protocols from the internet", "", "Restrict ingress CIDRs and allow only required protocols and ports.")
			continue
		}
		if protocol != "tcp" && protocol != "6" && protocol != "udp" && protocol != "17" {
			continue
		}
		from, fromOK := p.integer("fromPort")
		to, toOK := p.integer("toPort")
		if !fromOK || !toOK || from < 0 || to > 65535 || from > to {
			unknown(add, "ingress port range")
			continue
		}
		for _, port := range []int{22, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017} {
			if from <= port && to >= port {
				add("security-group-open-admin", finding.SeverityHigh, "Administrative or database port is open to the internet", fmt.Sprintf("Ingress includes port %d from 0.0.0.0/0 or ::/0.", port), "Restrict ingress CIDRs to intended clients or use private access.")
			}
		}
	}
}

func bucket(res resource, c fields, add emit) {
	setting := func(key string) json.RawMessage {
		for k, v := range res.Supplementary {
			if strings.EqualFold(k, key) {
				return v
			}
		}
		return c.get(key)
	}
	block, ok := object(setting("PublicAccessBlockConfiguration"))
	if !ok {
		unknown(add, "S3 bucket public access block")
	} else {
		for _, key := range []string{"blockPublicAcls", "ignorePublicAcls", "blockPublicPolicy", "restrictPublicBuckets"} {
			boolRule(block, key, "s3-public-block-disabled", "S3 bucket public access blocking is disabled", "Enable all four bucket-level public access block settings unless public access is intentional.", false, finding.SeverityMedium, func(id string, sev finding.Severity, title, detail, fix string) { add(id, sev, title, key, fix) })
		}
	}
	acl, ok := object(setting("AccessControlList"))
	if !ok {
		unknown(add, "S3 ACL")
	} else if grants, ok := acl.array("grants"); ok {
		for _, grant := range grants {
			grantee, ok := object(grant.get("grantee"))
			if !ok {
				unknown(add, "S3 ACL grantee")
				continue
			}
			uri := grantee.text("uri")
			if uri == "http://acs.amazonaws.com/groups/global/AllUsers" || uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
				add("s3-public-acl", finding.SeverityHigh, "S3 ACL grants access to a public group", "Effective access also depends on public access blocks and other policies.", "Remove public ACL grants or document the intended public access.")
			}
		}
	} else {
		unknown(add, "S3 ACL grants")
	}
	policy, ok := object(setting("BucketPolicy"))
	if !ok {
		unknown(add, "S3 bucket policy")
	} else {
		iam(policy.get("policyText"), true, add)
	}
}

func iam(raw json.RawMessage, trust bool, add emit) {
	doc, ok := object(raw)
	if !ok {
		unknown(add, "IAM or resource policy document")
		return
	}
	var statements []fields
	if statement, ok := object(doc.get("Statement")); ok {
		statements = []fields{statement}
	} else {
		statements, ok = doc.array("Statement")
		if !ok {
			unknown(add, "policy statements")
			return
		}
	}
	for _, s := range statements {
		effect := s.text("Effect")
		if effect != "Allow" && effect != "Deny" {
			unknown(add, "policy statement effect")
			continue
		}
		if effect == "Deny" {
			continue
		}
		conditions, _ := object(s.get("Condition"))
		condition := len(conditions) > 0
		sev := finding.SeverityHigh
		detail := "Other policies may restrict effective access; they are not evaluated."
		if condition {
			detail = "The statement includes conditions; their effect and other access controls are not evaluated."
		}
		if trust {
			principal := s.get("Principal")
			if len(principal) == 0 || bytes.Equal(principal, []byte("null")) {
				unknown(add, "resource policy principal")
				continue
			}
			wildcard := slices.Contains(stringsOf(principal), "*")
			if p, ok := object(principal); ok {
				for _, v := range p {
					if slices.Contains(stringsOf(v), "*") {
						wildcard = true
					}
				}
			}
			if wildcard {
				add("policy-public-principal", sev, "Resource or trust policy allows a wildcard principal", detail, "Limit principals to the intended identities and review policy conditions.")
			}
		} else {
			actions, resources := stringsOf(s.get("Action")), stringsOf(s.get("Resource"))
			if len(actions) == 0 || len(resources) == 0 {
				unknown(add, "policy actions or resources")
			} else if slices.Contains(actions, "*") && slices.Contains(resources, "*") {
				add("iam-admin-policy", sev, "IAM policy allows all actions on all resources", detail, "Replace wildcard permissions with the actions and resources the workload needs.")
			}
		}
	}
}

// AWS Config uses string CIDRs in some configurations and API-shaped objects in others.
func cidrs(raw json.RawMessage, key string) ([]string, bool) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, false
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	var out []string
	for _, entry := range entries {
		var s string
		if json.Unmarshal(entry, &s) != nil {
			obj, ok := object(entry)
			if !ok {
				return nil, false
			}
			s = obj.text(key)
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, false
		}
		out = append(out, prefix.Masked().String())
	}
	return out, true
}

func unique(found []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(found))
	for _, f := range found {
		key := f.ID + "\x00" + string(f.Severity) + "\x00" + f.Subject + "\x00" + f.Detail
		if !seen[key] {
			out = append(out, f)
			seen[key] = true
		}
	}
	return out
}

func (f fields) integer(key string) (int, bool) {
	raw := f.get(key)
	var n int
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	return n, true
}
