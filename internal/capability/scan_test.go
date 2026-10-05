package capability_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/securock/securock/internal/capability"
	"github.com/securock/securock/pkg/lockfile"
)

func TestFromMetadataInstallScript(t *testing.T) {
	got := capability.FromMetadata(capability.Metadata{
		HasInstallScript: true,
	})
	if !got.InstallScripts || !got.Shell {
		t.Fatalf("install script should imply shell: %+v", got)
	}
	ev := capability.Evidence(got)
	if ev.State != lockfile.CapChecked || ev.InstallScripts == nil || !*ev.InstallScripts {
		t.Fatalf("evidence = %+v", ev)
	}
}

func TestBehaviorExtraction(t *testing.T) {
	got := capability.FromMetadata(capability.Metadata{
		Scripts: map[string]string{
			"postinstall": `node -e "fetch('https://telemetry.example.com/x'); require('fs').writeFileSync('~/.ssh/id_rsa','x'); process.env.AWS_ACCESS_KEY_ID; require('child_process').exec('node-gyp rebuild')"`,
		},
	})
	beh := capability.Behavior(got)
	if beh.State != lockfile.CapChecked {
		t.Fatalf("state = %s", beh.State)
	}
	if !contains(beh.Network, "telemetry.example.com") {
		t.Fatalf("network = %v", beh.Network)
	}
	if beh.Files == nil || !contains(beh.Files.Write, "~/.ssh/id_rsa") {
		t.Fatalf("files.write = %v", beh.Files)
	}
	if !contains(beh.Environment, "AWS_ACCESS_KEY_ID") {
		t.Fatalf("environment = %v", beh.Environment)
	}
	if !contains(beh.Commands, "node-gyp") {
		t.Fatalf("commands = %v", beh.Commands)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestFromMetadataNativeDeps(t *testing.T) {
	got := capability.FromMetadata(capability.Metadata{
		Dependencies: map[string]string{"node-gyp": "^9.0.0"},
	})
	if !got.NativeCode {
		t.Fatal("node-gyp dependency should mark native_code")
	}
}

func TestScanSourcePatterns(t *testing.T) {
	// Minimal gzip+tar is awkward; exercise scanText via scripts metadata instead.
	got := capability.FromMetadata(capability.Metadata{
		Scripts: map[string]string{
			"postinstall": "node -e \"require('https'); process.env.FOO; require('fs').writeFileSync('x','y')\"",
		},
	})
	if !got.InstallScripts || !got.Network || !got.Environment {
		t.Fatalf("script body not scanned: %+v", got)
	}
	if got.Filesystem != lockfile.FilesystemWrite {
		t.Fatalf("filesystem = %s", got.Filesystem)
	}
}

func TestScanSourceReader(t *testing.T) {
	// Empty gzip stream should fail cleanly.
	err := capability.ScanSource(bytes.NewReader([]byte("not-a-tarball")), &capability.Findings{})
	if err == nil {
		t.Fatal("expected error for invalid gzip")
	}
}

func TestScanSourceRejectsOversizedJS(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := bytes.Repeat([]byte("a"), 512<<10+1)
	hdr := &tar.Header{Name: "package/big.js", Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	err := capability.ScanSource(bytes.NewReader(buf.Bytes()), &capability.Findings{})
	if err == nil {
		t.Fatal("expected oversized source file error")
	}
}
