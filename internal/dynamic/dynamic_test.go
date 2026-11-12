package dynamic_test

import (
	"github.com/securock/securock/internal/dynamic"
	"strings"
	"testing"
)

func TestScopeAndParameterSkipping(t *testing.T) {
	urls, skip, e := dynamic.Endpoints(strings.NewReader(`{"openapi":"3.0.0","paths":{"/a":{"get":{}},"//evil.test":{"get":{}},"/users/{id}":{"get":{}},"/delete":{"delete":{}}}}`), "https://app.test/")
	if e != nil || len(urls) != 1 || urls[0] != "https://app.test/a" || skip != 2 {
		t.Fatal(urls, skip, e)
	}
}

func TestServerBasePathsAndScope(t *testing.T) {
	for _, tc := range []struct {
		name, spec, target, want string
		skipped                  int
	}{
		{"root server", `{"servers":[{"url":"https://app.test/api/v1"}],"paths":{"/users":{"get":{}}}}`, "https://app.test/", "https://app.test/api/v1/users", 0},
		{"supplied base", `{"paths":{"/users":{"get":{}}}}`, "https://app.test/api/v1", "https://app.test/api/v1/users", 0},
		{"relative server", `{"servers":[{"url":"/v2"}],"paths":{"/users":{"get":{}}}}`, "https://app.test/", "https://app.test/v2/users", 0},
		{"operation override", `{"servers":[{"url":"/v1"}],"paths":{"/users":{"servers":[{"url":"/v2"}],"get":{"servers":[{"url":"/v3"}]}}}}`, "https://app.test/", "https://app.test/v3/users", 0},
		{"foreign server", `{"servers":[{"url":"https://other.test/v1"}],"paths":{"/users":{"get":{}}}}`, "https://app.test/", "", 1},
		{"server variables", `{"servers":[{"url":"https://app.test/{version}"}],"paths":{"/users":{"get":{}}}}`, "https://app.test/", "", 1},
		{"encoded traversal", `{"paths":{"/%2e%2e/users":{"get":{}}}}`, "https://app.test/api", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := strings.Replace(tc.spec, "{", `{"openapi":"3.0.0",`, 1)
			urls, skipped, err := dynamic.Endpoints(strings.NewReader(spec), tc.target)
			if err != nil || skipped != tc.skipped || strings.Join(urls, ",") != tc.want {
				t.Fatalf("urls=%v skipped=%d err=%v", urls, skipped, err)
			}
		})
	}
}
