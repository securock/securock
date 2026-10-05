package capability_test

import (
	"bytes"
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
