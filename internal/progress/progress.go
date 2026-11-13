// Package progress carries optional analysis status without changing report output.
package progress

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

type reporterKey struct{}

// WithReporter attaches a status callback to an analysis. The callback must be safe
// for concurrent use if the analysis runs work in parallel.
func WithReporter(ctx context.Context, report func(string)) context.Context {
	return context.WithValue(ctx, reporterKey{}, report)
}

// Report updates the current stage, if a caller requested status updates.
func Report(ctx context.Context, stage string) {
	if report, ok := ctx.Value(reporterKey{}).(func(string)); ok && report != nil {
		report(stage)
	}
}

// Display updates one terminal line until Stop clears it. Only trusted stage labels
// belong here: filenames, URLs and findings are deliberately kept in the report.
type Display struct {
	mu      sync.Mutex
	out     io.Writer
	stage   string
	width   func() int
	frame   int
	stopped bool
	done    chan struct{}
	wg      sync.WaitGroup
}

// Start begins a compact, animated status line. The caller must check that out is
// an interactive terminal and call Stop before writing regular output.
func Start(out io.Writer, stage string, width func() int) *Display {
	d := &Display{out: out, stage: stage, width: width, done: make(chan struct{})}
	d.draw()
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-d.done:
				return
			case <-ticker.C:
				d.mu.Lock()
				if !d.stopped {
					d.frame++
					d.draw()
				}
				d.mu.Unlock()
			}
		}
	}()
	return d
}

// Update replaces the stage without adding scrollback lines.
func (d *Display) Update(stage string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopped && d.stage != stage {
		d.stage = stage
		d.draw()
	}
}

func (d *Display) draw() {
	line := fmt.Sprintf("%c %s", "|/-\\"[d.frame%4], d.stage)
	width := 80
	if d.width != nil {
		if n := d.width(); n > 0 {
			width = n
		}
	}
	// Stage labels are ASCII. Leave the last column free to avoid terminal wrap.
	if len(line) >= width {
		line = line[:width-1]
	}
	fmt.Fprintf(d.out, "\r\x1b[2K%s", line)
}

// Stop joins the animation and clears the line, including on error. Repeated calls
// and late updates are harmless.
func (d *Display) Stop() {
	d.mu.Lock()
	if !d.stopped {
		d.stopped = true
		close(d.done)
		fmt.Fprint(d.out, "\r\x1b[2K")
	}
	d.mu.Unlock()
	d.wg.Wait()
}
