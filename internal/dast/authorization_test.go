package dast_test

import (
	"context"
	"fmt"
	"github.com/securock/securock/internal/dast"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObjectAuthorizationControls(t *testing.T) {
	bad, broken := false, false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer owner-token" {
			if broken {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"id":"record-one"}`)
			return
		}
		if bad {
			fmt.Fprint(w, `{"id":"record-one"}`)
		} else {
			w.WriteHeader(403)
		}
	}))
	defer s.Close()
	m, e := dast.ReadMatrix(strings.NewReader(`{"version":1,"actors":[{"id":"owner","bearer_env":"OWNER","anonymous":false},{"id":"other","bearer_env":"OTHER","anonymous":false}],"cases":[{"id":"tenant-isolation","path":"/api/records/1","allow":["owner"],"deny":["other"],"pointer":"/id","expected":"record-one"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	getenv := func(name string) string {
		if name == "OWNER" {
			return "owner-token"
		}
		return "other-token"
	}
	r, e := dast.Authorization(context.Background(), s.URL+"/api", m, getenv, nil)
	if e != nil || len(r.Findings) != 0 {
		t.Fatal(r, e)
	}
	bad = true
	r, e = dast.Authorization(context.Background(), s.URL+"/api", m, getenv, nil)
	if e != nil || len(r.Findings) != 1 || r.Findings[0].ID != "dast:authorization-bypass" {
		t.Fatal(r, e)
	}
	broken = true
	r, e = dast.Authorization(context.Background(), s.URL+"/api", m, getenv, nil)
	if e == nil || len(r.Findings) != 1 || r.Findings[0].ID != "dast:authorization-incomplete" {
		t.Fatal(r, e)
	}
	if strings.Contains(fmt.Sprint(r), "owner-token") {
		t.Fatal("credential leak")
	}
}
func TestAuthorizationRejectsAmbiguousMatrix(t *testing.T) {
	if _, e := dast.ReadMatrix(strings.NewReader(`{"version":1,"actors":[{"id":"a","anonymous":true},{"id":"a","anonymous":true}],"cases":[]}`)); e == nil {
		t.Fatal("duplicate actors")
	}
}
