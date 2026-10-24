package sast_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/securock/securock/internal/finding"
)

func TestApplicationCaseHit(t *testing.T) {
	c := applicationCase{file: "a.ts", rule: "sast:js/sql-injection", start: 3, end: 5}
	if c.hit(nil) {
		t.Fatal("no findings counted as a detection")
	}
	for _, tt := range []struct {
		name, file, rule string
		line             int
		nilLocation, hit bool
	}{
		{"first line", "a.ts", c.rule, 3, false, true},
		{"last line", "a.ts", c.rule, 5, false, true},
		{"previous handler", "a.ts", c.rule, 2, false, false},
		{"next handler", "a.ts", c.rule, 6, false, false},
		{"other file", "b.ts", c.rule, 4, false, false},
		{"other rule", "a.ts", "sast:js/xss", 4, false, false},
		{"incomplete analysis", "a.ts", "sast:analysis-incomplete", 4, false, false},
		{"no location", "a.ts", c.rule, 4, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{ID: tt.rule}
			if !tt.nilLocation {
				f.Location = &finding.Location{File: tt.file, Line: tt.line}
			}
			if hit := c.hit([]finding.Finding{f}); hit != tt.hit {
				t.Fatalf("hit = %t, want %t", hit, tt.hit)
			}
		})
	}
}

func TestApplicationRegression(t *testing.T) {
	for _, tt := range []struct {
		name                                          string
		vulnerable, required, knownFP, hit, wantError bool
	}{
		{"retained detection", true, true, false, true, false},
		{"lost detection", true, true, false, false, true},
		{"known miss", true, false, false, false, false},
		{"new detection", true, false, false, true, false},
		{"safe control", false, false, false, false, false},
		{"new false positive", false, false, false, true, true},
		{"known false positive", false, false, true, true, false},
		{"removed false positive", false, false, true, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := applicationCase{vulnerable: tt.vulnerable, required: tt.required, knownFP: tt.knownFP}
			if err := c.regression(tt.hit); (err != nil) != tt.wantError {
				t.Fatalf("error = %v, want error = %t", err, tt.wantError)
			}
		})
	}
}

func TestReadApplicationProject(t *testing.T) {
	root := t.TempDir()
	source := []byte("const a = 1\nconst b = 2\n")
	if err := os.WriteFile(filepath.Join(root, "a.js"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	input := applicationInput{"a.js", fmt.Sprintf("%x", sha256.Sum256(source))}
	c := applicationCase{"a.js", "sast:js/sql-injection", 1, 2, true, true, false}
	for _, tt := range []struct {
		name   string
		inputs []applicationInput
		cases  []applicationCase
		valid  bool
	}{
		{"valid", []applicationInput{input}, []applicationCase{c}, true},
		{"no inputs", nil, []applicationCase{c}, false},
		{"no labels", []applicationInput{input}, nil, false},
		{"changed source", []applicationInput{{input.file, "wrong"}}, []applicationCase{c}, false},
		{"missing source", []applicationInput{{"missing.js", input.sha256}}, []applicationCase{c}, false},
		{"duplicate input", []applicationInput{input, input}, []applicationCase{c}, false},
		{"parent path", []applicationInput{{"../a.js", input.sha256}}, []applicationCase{c}, false},
		{"absolute path", []applicationInput{{filepath.Join(root, input.file), input.sha256}}, []applicationCase{c}, false},
		{"unscanned label", []applicationInput{input}, []applicationCase{{"b.js", c.rule, 1, 2, true, true, false}}, false},
		{"zero start", []applicationInput{input}, []applicationCase{{c.file, c.rule, 0, 2, true, true, false}}, false},
		{"reversed range", []applicationInput{input}, []applicationCase{{c.file, c.rule, 2, 1, true, true, false}}, false},
		{"out of range", []applicationInput{input}, []applicationCase{{c.file, c.rule, 1, 4, true, true, false}}, false},
		{"missing rule", []applicationInput{input}, []applicationCase{{c.file, "", 1, 2, true, true, false}}, false},
		{"safe required detection", []applicationInput{input}, []applicationCase{{c.file, c.rule, 1, 2, false, true, false}}, false},
		{"vulnerable false positive", []applicationInput{input}, []applicationCase{{c.file, c.rule, 1, 2, true, false, true}}, false},
		{"duplicate label", []applicationInput{input}, []applicationCase{c, c}, false},
		{"overlapping label", []applicationInput{input}, []applicationCase{c, {c.file, c.rule, 2, 3, true, true, false}}, false},
		{"separate ranges", []applicationInput{input}, []applicationCase{{c.file, c.rule, 1, 1, true, true, false}, {c.file, c.rule, 2, 2, false, false, false}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files, err := readApplicationProject(root, applicationProject{tt.inputs, tt.cases})
			if (err == nil) != tt.valid {
				t.Fatalf("error = %v, want valid = %t", err, tt.valid)
			}
			if tt.valid && string(files[input.file]) != string(source) {
				t.Fatal("source bytes changed")
			}
		})
	}
}

func TestSingleFileApplications(t *testing.T) {
	inputs := []applicationInput{{file: "a.ts"}, {file: "b.ts"}}
	cases := []applicationCase{{file: "a.ts", start: 1}, {file: "b.ts", start: 2}, {file: "a.ts", start: 3}}
	projects, err := singleFileApplications(inputs, cases)
	if err != nil || len(projects) != 2 {
		t.Fatalf("projects = %v, error = %v", projects, err)
	}
	if len(projects[0].inputs) != 1 || projects[0].inputs[0].file != "a.ts" || len(projects[0].cases) != 2 || projects[0].cases[1].start != 3 || len(projects[1].cases) != 1 || projects[1].cases[0].file != "b.ts" {
		t.Fatal("variants or their labels were combined or lost")
	}
	if _, err := singleFileApplications(inputs[:1], cases); err == nil {
		t.Fatal("unscanned label silently dropped")
	}
	if _, err := singleFileApplications([]applicationInput{inputs[0], inputs[0]}, cases[:1]); err == nil {
		t.Fatal("duplicate input accepted")
	}
}
