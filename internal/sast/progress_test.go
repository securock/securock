package sast_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/securock/securock/internal/sast"
)

func TestAnalysisProgressPreservesFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import ("database/sql"; "net/http")
func handle(db *sql.DB, r *http.Request) { db.Query("SELECT " + r.FormValue("id")) }
`), 0600); err != nil {
		t.Fatal(err)
	}
	want, err := sast.Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	var stages []string
	got, err := sast.AnalyzeWith(dir, sast.Options{Progress: func(stage string) { stages = append(stages, stage) }})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || len(got) == 0 {
		t.Fatalf("progress changed findings: got=%+v want=%+v", got, want)
	}
	for _, stage := range []string{
		"sast: reading source, secrets and infrastructure",
		"sast: resolving Go types and imports",
		"sast: tracing data flow across functions",
		"sast: checking insecure API use",
	} {
		if !slices.Contains(stages, stage) {
			t.Fatalf("stage %q missing from %v", stage, stages)
		}
	}
}
