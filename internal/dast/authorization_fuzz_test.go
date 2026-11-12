package dast_test

import (
	"github.com/securock/securock/internal/dast"
	"strings"
	"testing"
)

func FuzzAuthorizationMatrix(f *testing.F) {
	f.Add(`{"version":1,"actors":[{"id":"owner","bearer_env":"OWNER","anonymous":false},{"id":"anonymous","bearer_env":"","anonymous":true}],"cases":[{"id":"private-record","path":"/records/1","allow":["owner"],"deny":["anonymous"],"pointer":"/id","expected":"one"}]}`)
	f.Add(`null`)
	f.Add(`{"version":1,"actors":[],"cases":[]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		matrix, e := dast.ReadMatrix(strings.NewReader(raw))
		if e == nil && (matrix.Version != 1 || len(matrix.Actors) < 2 || len(matrix.Actors) > 20 || len(matrix.Cases) == 0 || len(matrix.Cases) > 200) {
			t.Fatal("accepted matrix escaped parser limits")
		}
	})
}
