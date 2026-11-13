package progress_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/securock/securock/internal/progress"
)

func TestReporterIsOptionalAndScoped(t *testing.T) {
	parent := context.Background()
	var got string
	ctx := progress.WithReporter(parent, func(s string) { got = s })
	progress.Report(ctx, "reading source")
	progress.Report(parent, "unrelated scan")
	progress.Report(progress.WithReporter(parent, nil), "disabled")
	if got != "reading source" {
		t.Fatalf("stage = %q", got)
	}
}

func TestDisplayClearsAndIgnoresLateUpdates(t *testing.T) {
	var out bytes.Buffer
	d := progress.Start(&out, "reading source", nil)
	d.Update("tracing data flow")
	d.Stop()
	before := out.String()
	d.Update("should not appear")
	d.Stop()
	if out.String() != before {
		t.Fatal("display wrote after Stop")
	}
	if !strings.Contains(before, "reading source") || !strings.Contains(before, "tracing data flow") {
		t.Fatalf("missing stages: %q", before)
	}
	if strings.Contains(before, "\n") || !strings.HasSuffix(before, "\r\x1b[2K") {
		t.Fatalf("status must stay on one line and clear on stop: %q", before)
	}
}

func TestDisplayAdaptsToTerminalWidth(t *testing.T) {
	var out bytes.Buffer
	width := 20
	d := progress.Start(&out, "a very long analysis stage", func() int { return width })
	// The width callback is normally called by the ticker too. Stop immediately
	// before inspecting the rendered frames.
	d.Stop()
	for _, frame := range strings.Split(out.String(), "\r\x1b[2K") {
		if len(frame) >= width {
			t.Fatalf("frame wraps in %d columns: %q", width, frame)
		}
	}
	if !strings.Contains(out.String(), "a very long") {
		t.Fatalf("stage missing: %q", out.String())
	}
}

type frameWriter struct {
	frames chan string
}

func (w frameWriter) Write(p []byte) (int, error) {
	select {
	case w.frames <- string(p):
	default:
	}
	return len(p), nil
}

func TestDisplayAnimatesDuringSilentWork(t *testing.T) {
	w := frameWriter{frames: make(chan string, 10)}
	d := progress.Start(w, "resolving imports", nil)
	defer d.Stop()
	first := <-w.frames
	select {
	case next := <-w.frames:
		if first == next || !strings.Contains(next, "resolving imports") {
			t.Fatalf("animation did not advance: %q -> %q", first, next)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no status refresh during silent work")
	}
}

func TestDisplayConcurrentUpdatesAndStop(t *testing.T) {
	var out bytes.Buffer
	d := progress.Start(&out, "initial", nil)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for range 20 {
				d.Update("parallel work")
			}
			d.Stop()
		})
	}
	wg.Wait()
	if !strings.HasSuffix(out.String(), "\r\x1b[2K") {
		t.Fatalf("display left behind after stop: %q", out.String())
	}
}
