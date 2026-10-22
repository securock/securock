package evidence_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/securock/securock/internal/ecosystem"
	"github.com/securock/securock/internal/evidence"
)

// gateCollector returns only once the other collector has started, so collectors that
// run one after the other never finish.
type gateCollector struct {
	started chan<- struct{}
	peer    <-chan struct{}
	err     error
}

func (g gateCollector) Collect(context.Context, []ecosystem.Dependency) (map[string]evidence.Record, error) {
	close(g.started)
	select {
	case <-g.peer:
	case <-time.After(5 * time.Second):
		return nil, errors.New("peer collector did not start")
	}
	return map[string]evidence.Record{}, g.err
}

func TestMultiRunsCollectorsTogether(t *testing.T) {
	a, b := make(chan struct{}), make(chan struct{})
	m := &evidence.Multi{Collectors: []evidence.Collector{
		gateCollector{started: a, peer: b},
		gateCollector{started: b, peer: a},
	}}
	if _, err := m.Collect(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestMultiReportsFirstCollectorError(t *testing.T) {
	a, b := make(chan struct{}), make(chan struct{})
	first := errors.New("first")
	m := &evidence.Multi{Collectors: []evidence.Collector{
		gateCollector{started: a, peer: b, err: first},
		gateCollector{started: b, peer: a, err: errors.New("second")},
	}}
	if _, err := m.Collect(context.Background(), nil); !errors.Is(err, first) {
		t.Fatalf("err = %v, want %v", err, first)
	}
}
