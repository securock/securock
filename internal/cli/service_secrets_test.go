package cli_test

import (
	"bytes"
	"encoding/base64"
	"github.com/securock/securock/internal/control"
	"github.com/securock/securock/internal/identity"
	"os"
	"path/filepath"
	"testing"
)

func TestMountedSecretsOverrideEnvironmentForRecovery(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	state := filepath.Join(root, "state")
	key, seed := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	store, e := control.Open(state, key, []identity.Binding{{Subject: "alice", Tenant: "acme", Roles: []string{"admin"}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = store.SetSigner(seed); e != nil {
		t.Fatal(e)
	}
	_ = store.Close()
	keyFile, seedFile := filepath.Join(root, "key"), filepath.Join(root, "seed")
	_ = os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0600)
	_ = os.WriteFile(seedFile, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0600)
	t.Setenv("SECUROCK_STATE_KEY", "invalid")
	t.Setenv("SECUROCK_AUDIT_SEED", "invalid")
	backup := filepath.Join(root, "backup.enc")
	runCLI(t, "control", backup, "--state-dir", state, "--key-file", keyFile, "--audit-key-file", seedFile, "--offline")
	restored := filepath.Join(root, "restored")
	runCLI(t, "control", backup, "--restore", "--state-dir", restored, "--key-file", keyFile, "--audit-key-file", seedFile, "--offline")
	if _, e = os.Stat(filepath.Join(restored, "state.enc")); e != nil {
		t.Fatal(e)
	}
	_ = os.WriteFile(keyFile, []byte("not base64"), 0600)
	runCLIExpectError(t, "control", filepath.Join(root, "invalid.enc"), "--state-dir", state, "--key-file", keyFile, "--audit-key-file", seedFile, "--offline")
}
