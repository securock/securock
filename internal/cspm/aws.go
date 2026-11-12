package cspm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const CollectionTimeout = 60 * time.Second

// AWSCommand contains only read-only AWS Config arguments; no shell is involved.
func AWSCommand(region, profile string) ([]string, error) {
	if !regexp.MustCompile(`^[a-z]{2,4}(?:-[a-z0-9]+)+-\d+$`).MatchString(region) {
		return nil, fmt.Errorf("a valid AWS region is required")
	}
	if profile != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*$`).MatchString(profile) {
		return nil, fmt.Errorf("invalid AWS profile name")
	}
	types := make([]string, len(ResourceTypes))
	for i, typ := range ResourceTypes {
		types[i] = "'" + typ + "'"
	}
	args := []string{"configservice", "select-resource-config", "--expression", "SELECT resourceId, resourceType, accountId, awsRegion, configuration WHERE resourceType IN (" + strings.Join(types, ",") + ")", "--region", region, "--output", "json", "--no-cli-pager"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return args, nil
}

type boundedBuffer struct{ data bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > MaxInventoryBytes {
		return 0, fmt.Errorf("AWS Config output exceeds size limit")
	}
	return b.data.Write(p)
}

// CollectAWS uses the user's AWS CLI credentials and auto-pagination, without writing
// a snapshot to disk. Provider stderr is discarded because it may contain sensitive data.
func CollectAWS(ctx context.Context, region, profile string) ([]byte, error) {
	args, err := AWSCommand(region, profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "aws", args...)
	var stdout boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("AWS Config collection failed: check AWS CLI installation, credentials, recorder coverage, region, and config:SelectResourceConfig permission")
	}
	return stdout.data.Bytes(), nil
}
