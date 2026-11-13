package sast_test

import (
	"slices"
	"testing"
)

// Taint stored in a package-level variable reaches only the functions that read
// it, wherever they are declared: a reader analyzed before the writer must be
// analyzed again once the variable gains taint.
func TestPackageGlobalTaintReachesEarlierReaders(t *testing.T) {
	const header = "package main\nimport (\"database/sql\"; \"net/http\")\nvar db *sql.DB\n"
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"reader before writer", header + `var stored string
func read() { db.Query("SELECT " + stored) }
func write(r *http.Request) { stored = r.FormValue("q") }
`, []string{"sast:go/sql-injection"}},
		{"reader after writer", header + `var stored string
func write(r *http.Request) { stored = r.FormValue("q") }
func read() { db.Query("SELECT " + stored) }
`, []string{"sast:go/sql-injection"}},
		{"reader through a call chain", header + `var stored string
func read() { db.Query("SELECT " + load()) }
func load() string { return stored }
func write(r *http.Request) { stored = r.FormValue("q") }
`, []string{"sast:go/sql-injection"}},
		{"global written with a constant", header + `var stored string
func read() { db.Query("SELECT " + stored) }
func write() { stored = "fixed" }
`, nil},
		{"other global is not tainted", header + `var stored, other string
func read() { db.Query("SELECT " + other) }
func write(r *http.Request) { stored = r.FormValue("q") }
`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := analyze(t, map[string]string{"a.go": tc.src}); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
