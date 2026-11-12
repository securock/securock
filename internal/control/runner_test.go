package control_test

import (
	"encoding/json"
	"github.com/securock/securock/internal/control"
	"testing"
)

func TestRunnerLeaseCancellationAndIsolation(t *testing.T) {
	s, token, _ := fixture(t)
	a := token("alice")
	robot := token("robot")
	request(s, a, "POST", "/api/v1/projects", `{"id":"repo","name":"Repo","owner":"team"}`)
	request(s, a, "POST", "/api/v1/jobs", `{"id":"scan","project":"repo"}`)
	if request(s, token("dev"), "POST", "/api/v1/runner/claim", `{"projects":["repo"]}`).Code != 403 {
		t.Fatal("developer leased")
	}
	w := request(s, robot, "POST", "/api/v1/runner/claim", `{"projects":["repo"]}`)
	var v struct {
		Data control.Job `json:"data"`
	}
	if json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Data.Lease == "" {
		t.Fatal(w.Body.String())
	}
	w2 := request(s, robot, "POST", "/api/v1/runner/claim", `{"projects":["repo"]}`)
	if w2.Body.String() != w.Body.String() {
		t.Fatal("claim not idempotent")
	}
	body := `{"id":"scan","lease":"` + v.Data.Lease + `","report":{"tool":"security","findings":[]},"failed":false}`
	if request(s, token("bob"), "POST", "/api/v1/runner/complete", body).Code != 409 {
		t.Fatal("cross tenant lease")
	}
	request(s, a, "DELETE", "/api/v1/jobs/scan", "")
	if request(s, robot, "POST", "/api/v1/runner/complete", body).Code != 409 {
		t.Fatal("cancelled completion")
	}
}
