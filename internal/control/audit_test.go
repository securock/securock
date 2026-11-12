package control_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/securock/securock/internal/control"
	"testing"
	"time"
)

func TestApprovalsAndSignedAudit(t *testing.T) {
	s, token, _ := fixture(t)
	a := token("alice")
	body := `{"id":"exception","artifact":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rule":"sast:test","reason":"temporary mitigation","expires":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
	if w := request(s, a, "POST", "/api/v1/approvals", body); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if request(s, a, "PUT", "/api/v1/approvals/exception", `{"status":"approved"}`).Code != 409 {
		t.Fatal("self approval")
	}
	if w := request(s, token("dev"), "PUT", "/api/v1/approvals/exception", `{"status":"approved"}`); w.Code != 409 {
		t.Fatal("developer approval")
	}
	w := request(s, a, "GET", "/api/v1/audit", "")
	var envelope struct {
		Data control.AuditExport `json:"data"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &envelope); e != nil {
		t.Fatal(e)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	if e := control.VerifyAudit(envelope.Data, public); e != nil {
		t.Fatal(e)
	}
	if len(envelope.Data.Events) != 1 {
		t.Fatal("failed mutations audited as successful")
	}
	envelope.Data.Events[0].Actor = "forged"
	if e := control.VerifyAudit(envelope.Data, public); e == nil {
		t.Fatal("audit forgery")
	}
	other, _ := base64.StdEncoding.DecodeString(envelope.Data.PublicKey)
	other[0] ^= 1
	if e := control.VerifyAudit(envelope.Data, ed25519.PublicKey(other)); e == nil {
		t.Fatal("untrusted signer")
	}
}
