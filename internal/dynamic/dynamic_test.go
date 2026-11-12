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
