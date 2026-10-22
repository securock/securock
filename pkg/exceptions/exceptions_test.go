package exceptions_test

import (
	"strings"
	"testing"
	"time"

	"github.com/securock/securock/pkg/exceptions"
)

func day(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestExpiredIncludesTheLastDay(t *testing.T) {
	e := exceptions.Exception{Expires: "2026-06-30"}
	tests := []struct {
		now  string
		want bool
	}{
		{"2026-06-30T00:00:00Z", false},
		{"2026-06-30T23:59:59Z", false},
		{"2026-07-01T00:00:00Z", true},
		{"2026-06-30T23:59:59-05:00", true},
	}
	for _, tt := range tests {
		if got := e.Expired(day(tt.now)); got != tt.want {
			t.Errorf("%s: expired = %v, want %v", tt.now, got, tt.want)
		}
	}
	if !(exceptions.Exception{Expires: "soon"}).Expired(day("2026-01-01T00:00:00Z")) {
		t.Error("an unreadable date must count as expired")
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		name      string
		ex        exceptions.Exception
		id, subj  string
		wantMatch bool
	}{
		{"any package", exceptions.Exception{ID: "capability:network"}, "capability:network", "npm:a@1", true},
		{"other id", exceptions.Exception{ID: "capability:network"}, "capability:shell", "npm:a@1", false},
		{"exact artifact", exceptions.Exception{ID: "x", Subject: "npm:a@1"}, "x", "npm:a@1", true},
		{"other version", exceptions.Exception{ID: "x", Subject: "npm:a@1"}, "x", "npm:a@2", false},
		{"any version", exceptions.Exception{ID: "x", Subject: "npm:a"}, "x", "npm:a@2", true},
		{"any version with filename", exceptions.Exception{ID: "x", Subject: "pypi:a"}, "x", "pypi:a@2#a-2.whl", true},
		{"name prefix is not a match", exceptions.Exception{ID: "x", Subject: "npm:a"}, "x", "npm:ab@2", false},
		{"other ecosystem", exceptions.Exception{ID: "x", Subject: "npm:a"}, "x", "pypi:a@2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ex.Matches(tt.id, tt.subj); got != tt.wantMatch {
				t.Fatalf("got %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	ok := exceptions.Exception{ID: "known-vulnerability:GHSA-1", Reason: "not reachable", Expires: "2026-12-31"}
	tests := []struct {
		name    string
		doc     exceptions.Document
		wantErr string
	}{
		{"valid", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{ok}}, ""},
		{"empty", exceptions.Document{Version: 1}, ""},
		{"wrong version", exceptions.Document{Version: 2}, "unsupported"},
		{"no id", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{{Reason: "r", Expires: "2026-12-31"}}}, "id"},
		{"spaces in id", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{{ID: "a b", Reason: "r", Expires: "2026-12-31"}}}, "id"},
		{"no reason", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{{ID: "a", Expires: "2026-12-31"}}}, "reason"},
		{"no expiry", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{{ID: "a", Reason: "r"}}}, "expires is required"},
		{"bad date", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{{ID: "a", Reason: "r", Expires: "12/31/2026"}}}, "YYYY-MM-DD"},
		{"duplicate", exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{ok, ok}}, "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := exceptions.Validate(tt.doc)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalizeSorts(t *testing.T) {
	doc := exceptions.Document{Version: 1, Exceptions: []exceptions.Exception{
		{ID: "b"}, {ID: "a", Subject: "npm:z"}, {ID: "a", Subject: "npm:y"},
	}}
	got := exceptions.Canonicalize(doc).Exceptions
	if got[0].Subject != "npm:y" || got[1].Subject != "npm:z" || got[2].ID != "b" {
		t.Fatalf("order: %+v", got)
	}
	if doc.Exceptions[0].ID != "b" {
		t.Fatal("Canonicalize must not reorder its input")
	}
}
