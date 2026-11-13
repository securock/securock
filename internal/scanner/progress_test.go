package scanner_test

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/securock/securock/internal/progress"
	"github.com/securock/securock/internal/scanner"
)

func TestScanProgressPreservesResults(t *testing.T) {
	for _, offline := range []bool{true, false} {
		opts := scanner.Options{Path: "../ecosystem/npm/testdata", Offline: offline, Client: fakeOSV{}, Evidence: fakeEvidence{}}
		want, err := scanner.Scan(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		var stages []string
		ctx := progress.WithReporter(context.Background(), func(stage string) { stages = append(stages, stage) })
		got, err := scanner.Scan(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatal("progress changed dependency results")
		}
		if !slices.Contains(stages, "dependencies: reading package lockfiles") || !slices.Contains(stages, "dependencies: evaluating trust and policy") {
			t.Fatalf("missing dependency stages: %v", stages)
		}
		if remote := slices.Contains(stages, "dependencies: querying vulnerabilities and registry evidence"); remote == offline {
			t.Fatalf("remote stage = %v with offline = %v", remote, offline)
		}
	}
}
