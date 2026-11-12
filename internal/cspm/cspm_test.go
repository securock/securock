package cspm_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/securock/securock/internal/cspm"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/schemas"
)

func snapshot(typ string, config any, supplementary any) string {
	raw, _ := json.Marshal(map[string]any{"configurationItems": []any{map[string]any{
		"resourceType": typ, "resourceId": "resource-1", "accountId": "123456789012", "awsRegion": "ap-northeast-1", "configuration": config, "supplementaryConfiguration": supplementary,
	}}})
	return string(raw)
}
func check(t *testing.T, raw string) finding.Report {
	t.Helper()
	report, err := cspm.Read(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(report)
	if err := schemas.Validate("cspm-report.schema.json", encoded); err != nil {
		t.Fatalf("%v\n%s", err, encoded)
	}
	return report
}
func has(r finding.Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == "cspm:"+id {
			return true
		}
	}
	return false
}

func TestSecurityGroupRules(t *testing.T) {
	for _, tt := range []struct {
		name, config string
		want         bool
	}{
		{"SSH IPv4 API shape", `{"ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":[{"cidrIp":"0.0.0.0/0"}]}]}`, true},
		{"RDP IPv6 Config shape", `{"ipPermissions":[{"ipProtocol":"6","fromPort":3389,"toPort":3389,"ipv6Ranges":["::/0"]}]}`, true},
		{"all protocols", `{"ipPermissions":[{"ipProtocol":"-1","ipRanges":["0.0.0.0/0"]}]}`, true},
		{"port range", `{"ipPermissions":[{"ipProtocol":"tcp","fromPort":1,"toPort":65535,"ipRanges":["0.0.0.0/0"]}]}`, true},
		{"private SSH", `{"ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":["10.0.0.0/8"]}]}`, false},
		{"public HTTPS", `{"ipPermissions":[{"ipProtocol":"tcp","fromPort":443,"toPort":443,"ipRanges":["0.0.0.0/0"]}]}`, false},
		{"empty ingress", `{"ipPermissions":[]}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := check(t, snapshot("AWS::EC2::SecurityGroup", json.RawMessage(tt.config), nil))
			if has(report, "security-group-open-admin") != tt.want {
				t.Fatalf("findings: %+v", report.Findings)
			}
		})
	}
}

func TestRDSAndTrail(t *testing.T) {
	rds := check(t, snapshot("AWS::RDS::DBInstance", map[string]any{"publiclyAccessible": true, "storageEncrypted": false, "backupRetentionPeriod": 0, "masterUserPassword": "must-not-appear-in-report"}, nil))
	for _, id := range []string{"rds-public", "rds-unencrypted", "rds-backups-disabled"} {
		if !has(rds, id) {
			t.Errorf("missing %s", id)
		}
	}
	raw, _ := json.Marshal(rds)
	if strings.Contains(string(raw), "must-not-appear-in-report") {
		t.Fatal("configuration secret leaked")
	}
	safe := check(t, snapshot("AWS::RDS::DBInstance", map[string]any{"PubliclyAccessible": false, "StorageEncrypted": true, "BackupRetentionPeriod": 7}, nil))
	if safe.AtLeast(finding.SeverityLow) != 0 {
		t.Fatalf("safe database flagged: %+v", safe)
	}
	trail := check(t, snapshot("AWS::CloudTrail::Trail", map[string]any{"isMultiRegionTrail": false, "logFileValidationEnabled": false}, nil))
	if !has(trail, "cloudtrail-single-region") || !has(trail, "cloudtrail-validation-disabled") {
		t.Fatal(trail)
	}
}

func TestMissingNullAndMalformedSettingsStayUnknown(t *testing.T) {
	for _, config := range []string{`{"publiclyAccessible":null}`, `{"publiclyAccessible":"false"}`, `{"storageEncrypted":true}`} {
		report := check(t, snapshot("AWS::RDS::DBInstance", json.RawMessage(config), nil))
		if !has(report, "check-unavailable") || has(report, "rds-public") || has(report, "rds-unencrypted") {
			t.Fatalf("unknown treated as evaluated: %+v", report)
		}
	}
	report := check(t, snapshot("AWS::EC2::SecurityGroup", json.RawMessage(`{"ipPermissions":[{"ipProtocol":"tcp","fromPort":null,"toPort":null,"ipRanges":["0.0.0.0/0"]}]}`), nil))
	if !has(report, "check-unavailable") {
		t.Fatal("null ports silently skipped")
	}
}

func TestIAMStatementBoundariesAndConditions(t *testing.T) {
	for _, tt := range []struct {
		name, doc string
		severity  finding.Severity
	}{
		{"unconditional admin", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, finding.SeverityHigh},
		{"empty condition stays high", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{ }}}`, finding.SeverityHigh},
		{"arrays and conditions", `{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"],"Condition":{"StringEquals":{"aws:PrincipalOrgID":"org-1"}}}]}`, finding.SeverityHigh},
		{"deny does not grant", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, ""},
		{"separate statements do not combine", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::one"},{"Effect":"Deny","Action":"read","Resource":"*"}]}`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := check(t, snapshot("AWS::IAM::Policy", map[string]any{"policyDocument": tt.doc}, nil))
			got := finding.Severity("")
			for _, f := range report.Findings {
				if f.ID == "cspm:iam-admin-policy" {
					got = f.Severity
				}
			}
			if got != tt.severity {
				t.Fatalf("severity %s, want %s", got, tt.severity)
			}
		})
	}
	report := check(t, snapshot("AWS::IAM::Policy", json.RawMessage(`{"policyVersionList":[{"isDefaultVersion":false,"document":{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}},{"isDefaultVersion":true,"document":{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}}]}`), nil))
	if has(report, "iam-admin-policy") {
		t.Fatal("checked a non-default policy version")
	}
}

func TestS3SupplementaryAndRoleTrust(t *testing.T) {
	report := check(t, snapshot("AWS::S3::Bucket", map[string]any{"name": "bucket"}, map[string]any{
		"PublicAccessBlockConfiguration": `{"blockPublicAcls":false,"ignorePublicAcls":true,"blockPublicPolicy":true,"restrictPublicBuckets":true}`,
		"AccessControlList":              `{"grants":[{"grantee":{"uri":"http://acs.amazonaws.com/groups/global/AllUsers"},"permission":"READ"}]}`,
		"BucketPolicy":                   `{"policyText":"{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket/*\"}}"}`,
	}))
	for _, id := range []string{"s3-public-acl", "s3-public-block-disabled", "policy-public-principal"} {
		if !has(report, id) {
			t.Errorf("missing %s: %+v", id, report)
		}
	}
	role := check(t, snapshot("AWS::IAM::Role", json.RawMessage(`{"assumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}},"rolePolicyList":[]}`), nil))
	if !has(role, "policy-public-principal") {
		t.Fatal(role)
	}
}

func TestInventoryFormatsAndFailures(t *testing.T) {
	original := snapshot("AWS::CloudTrail::Trail", map[string]any{"isMultiRegionTrail": true, "logFileValidationEnabled": true}, nil)
	var envelope map[string][]json.RawMessage
	json.Unmarshal([]byte(original), &envelope)
	wrapped, _ := json.Marshal(map[string]any{"Results": []string{string(envelope["configurationItems"][0])}})
	one := check(t, original)
	two := check(t, string(wrapped))
	a, _ := json.Marshal(one)
	b, _ := json.Marshal(two)
	if string(a) != string(b) {
		t.Fatal("snapshot and CLI results differ")
	}
	for _, raw := range []string{
		`{}`, `{`, `{"Results":["invalid"]}`, `{"configurationItems":[]}`, `{"Results":[],"NextToken":"more"}`,
		`{"configurationItems":[],"Results":[]}`, snapshot("AWS::RDS::DBInstance", nil, nil),
		`{"configurationItems":[{"resourceType":"AWS::RDS::DBInstance","resourceId":"db","configuration":{}}]}`,
	} {
		if _, err := cspm.Read(strings.NewReader(raw)); err == nil {
			t.Errorf("accepted invalid/incomplete snapshot %s", raw)
		}
	}
	duplicate := `{"configurationItems":[` + string(envelope["configurationItems"][0]) + `,` + string(envelope["configurationItems"][0]) + `]}`
	if _, err := cspm.Read(strings.NewReader(duplicate)); err == nil {
		t.Fatal("accepted duplicate identity")
	}
	if _, err := cspm.Read(strings.NewReader(strings.Repeat(" ", cspm.MaxInventoryBytes+1))); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
}

func TestCollectionCommandIsReadOnlyAndValidatesArguments(t *testing.T) {
	args, err := cspm.AWSCommand("ap-northeast-1", "audit-profile")
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "configservice" || args[1] != "select-resource-config" || !strings.Contains(args[3], "configuration") {
		t.Fatal(args)
	}
	for _, pair := range [][2]string{{"", ""}, {"--endpoint-url", ""}, {"us-east-1", "--debug"}, {"us-east-1", "name;echo secret"}} {
		if _, err := cspm.AWSCommand(pair[0], pair[1]); err == nil {
			t.Errorf("accepted %v", pair)
		}
	}
}

func TestConditionedPolicyCannotSuppressUnconditionalAdmin(t *testing.T) {
	config := json.RawMessage(`{"assumeRolePolicyDocument":{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}},"rolePolicyList":[{"policyDocument":{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"org-1"}}}}},{"policyDocument":{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}}]}`)
	report := check(t, snapshot("AWS::IAM::Role", config, nil))
	if report.AtLeast(finding.SeverityHigh) == 0 {
		t.Fatal("conditioned policy suppressed the unconditional admin finding")
	}
}

func TestMalformedCIDRAndEncodedConfiguration(t *testing.T) {
	malformed := check(t, snapshot("AWS::EC2::SecurityGroup", json.RawMessage(`{"ipPermissions":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":["not-a-cidr"],"ipv6Ranges":[]}]}`), nil))
	if !has(malformed, "check-unavailable") {
		t.Fatal("invalid CIDR was silently treated as private")
	}
	encoded := check(t, snapshot("AWS::RDS::DBInstance", `{"publiclyAccessible":true,"storageEncrypted":true,"backupRetentionPeriod":7}`, nil))
	if !has(encoded, "rds-public") {
		t.Fatal("JSON-encoded configuration was not inspected")
	}
}
