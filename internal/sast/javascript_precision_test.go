package sast_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/securock/securock/internal/sast"
)

func TestJavaScriptStringGuards(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       []string
	}{
		{"reject non-string", "if (typeof req.body.id !== 'string') return; User.findOne({_id: req.body.id});", nil},
		{"positive string branch", "if (typeof req.body.id === 'string') User.findOne({_id: req.body.id});", nil},
		{"bracket string guard", "if (typeof req.body['id'] !== 'string') return; User.findOne({_id: req.body['id']});", nil},
		{"reverse comparison", "if ('string' !== typeof req.body.id) return; User.findOne({_id: req.body.id});", nil},
		{"local string guard", "let id = req.body.id; if (typeof id !== 'string') return; User.findOne({_id: id});", nil},
		{"both validations required", "if (typeof req.body.id !== 'string' || typeof req.body.role !== 'string') return; User.findOne({_id: req.body.id, role: req.body.role});", nil},
		{"nonterminating guard", "if (typeof req.body.id !== 'string') {} User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
		{"wrong direction", "if (typeof req.body.id === 'string') return; User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
		{"only one validation required", "if (typeof req.body.id !== 'string' && typeof req.body.role !== 'string') return; User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
		{"object check", "if (typeof req.body.id !== 'object') return; User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
		{"reassigned local", "let id = req.body.id; if (typeof id !== 'string') return; id = req.body.other; User.findOne({_id: id});", []string{"sast:js/nosql-injection"}},
		{"reassigned field", "if (typeof req.body.id !== 'string') return; req.body.id = req.body.other; User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
		{"string is not SQL escaping", "if (typeof req.body.id !== 'string') return; db.query('SELECT ' + req.body.id);", []string{"sast:js/sql-injection"}},
		{"string is not shell escaping", "if (typeof req.body.id !== 'string') return; cp.exec(req.body.id);", []string{"sast:js/command-injection"}},
		{"string is not code escaping", "if (typeof req.body.id !== 'string') return; eval(req.body.id);", []string{"sast:js/code-injection"}},
		{"stringification is not validation", "if (typeof req.body.id.toString() !== 'string') return; User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
		{"call result is not validation", "if (typeof String(req.body.id) !== 'string') return; User.findOne({_id: req.body.id});", []string{"sast:js/nosql-injection"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "import * as cp from 'child_process';\nexport function handle(req: any) {\n" + tt.body + "\n}\n"
			if got := slices.Compact(analyze(t, map[string]string{"a.ts": src})); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJavaScriptQueryBuilderLocations(t *testing.T) {
	for _, tt := range []struct {
		name, builder string
		want          bool
	}{
		{"captured return", "const make = () => ({$where: 'this.name == ' + value});", true},
		{"nested captured return", "const make = () => { const inner = () => ({$where: value}); return inner(); };", true},
		{"string conversion does not escape code", "const make = () => ({$where: String(value)});", true},
		{"numeric conversion", "const make = () => ({$where: Number(value)});", false},
		{"reassigned builder", "let make = () => ({$where: value}); make = () => ({name: 'fixed'});", false},
		{"ordinary fields do not identify an unknown find receiver", "const make = () => ({name: value});", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "function handle(req) {\nconst value = req.query.name;\n" + tt.builder + "\nrecords.find(make());\n}\n"
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			findings, err := sast.Analyze(dir)
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			for _, f := range findings {
				if f.ID == "sast:analysis-incomplete" {
					t.Fatalf("analysis incomplete: %v", f)
				}
				if f.ID == "sast:js/nosql-injection" && f.Location != nil && f.Location.Line == 4 {
					hit = true
				}
			}
			if hit != tt.want {
				t.Fatalf("query-use hit = %t, want %t; findings: %v", hit, tt.want, findings)
			}
		})
	}
}

func TestJavaScriptIncompatiblePrefixes(t *testing.T) {
	for _, tt := range []struct {
		name, check string
		want        []string
	}{
		{"always rejecting OR", "if (!q.startsWith('apple') || !q.startsWith('orange')) return;", nil},
		{"unreachable AND branch", "if (q.startsWith('apple') && q.startsWith('orange')) { db.query('SELECT ' + q); return; } return;", nil},
		{"overlapping prefixes", "if (!q.startsWith('apple') || !q.startsWith('app')) return;", []string{"sast:js/sql-injection"}},
		{"same prefix", "if (!q.startsWith('apple') || !q.startsWith('apple')) return;", []string{"sast:js/sql-injection"}},
		{"empty prefix", "if (!q.startsWith('apple') || !q.startsWith('')) return;", []string{"sast:js/sql-injection"}},
		{"unknown prefix", "if (!q.startsWith('apple') || !q.startsWith(req.query.prefix)) return;", []string{"sast:js/sql-injection"}},
		{"different receivers", "if (!q.startsWith('apple') || !other.startsWith('orange')) return;", []string{"sast:js/sql-injection"}},
		{"allow either prefix", "if (!q.startsWith('apple') && !q.startsWith('orange')) return;", []string{"sast:js/sql-injection"}},
		{"opaque expression between checks", "if (!q.startsWith('apple') || change(q) || !q.startsWith('orange')) return;", []string{"sast:js/sql-injection"}},
		{"escaped prefixes stay conservative", `if (!q.startsWith('a') || !q.startsWith('\x61b')) return;`, []string{"sast:js/sql-injection"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "function handle(req) {\nconst q = req.query.q; const other = req.query.other;\n" + tt.check + "\ndb.query('SELECT ' + q);\n}\n"
			if got := slices.Compact(analyze(t, map[string]string{"a.js": src})); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
