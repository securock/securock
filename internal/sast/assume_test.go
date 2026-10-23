package sast_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/securock/securock/internal/sast"
)

func TestAssumeParams(t *testing.T) {
	const src = `package main
import ("os/exec"; "net/http")
type sink struct{ Handler func(string) }
func run(in string) { exec.Command("sh", "-c", in).Run() }
func safe(in string) { exec.Command("echo", in).Run() }
func called(in string) { exec.Command("sh", "-c", in).Run() }
func main() {
	_ = []sink{{Handler: run}, {Handler: safe}}
	called("ls")
	http.ListenAndServe(":80", nil)
}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ids := func(opts sast.Options) []string {
		got, err := sast.AnalyzeWith(dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range got {
			out = append(out, f.ID+" "+f.Subject)
		}
		slices.Sort(out)
		return out
	}
	if got := ids(sast.Options{}); len(got) != 0 {
		t.Fatalf("default mode reported %v", got)
	}
	got := ids(sast.Options{AssumeParams: true})
	want := []string{"sast:go/command-injection main.go#run/exec.Command"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
