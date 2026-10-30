package main

import (
	"fmt"
	"sync"
	"sync/atomic"
)

import "github.com/takehaya/bpf-ninja/internal/capture"

// One control belongs to one probe/capture, including all its shards.
type captureControl struct {
	hookRuns      bool
	runIncomplete atomic.Bool
	observe       func()
	runErrMu      sync.Mutex
	runErr        error
	written       atomic.Uint64
	limited       atomic.Uint64
	nullRecords   atomic.Uint64
	quiesce       func() error
	blockTag      func(uint32) error
	stopTag       func(uint32) error
	barrier       func() func() (bool, error)
	stats         *capture.SessionStats
	outputErr     *outputFailure
}

func (c *captureControl) stopBeforeDrain(stop func(), readerErr func() error, failure *outputFailure) func() {
	return func() {
		if c.quiesce != nil {
			failure.record(c.quiesce())
		}
		stop()
		failure.record(readerErr())
	}
}

// observeRunLoss keeps capture and per-tag finalization running. The summary
// reports the sticky loss after readers drain and shards merge.
func (c *captureControl) observeRunLoss(incomplete bool, diagnosticErr error) {
	if incomplete || diagnosticErr != nil {
		c.runIncomplete.Store(true)
	}
	if diagnosticErr != nil {
		c.runErrMu.Lock()
		if c.runErr == nil {
			c.runErr = diagnosticErr
		}
		c.runErrMu.Unlock()
	}
}

func (c *captureControl) runDiagnosticError() error {
	c.runErrMu.Lock()
	defer c.runErrMu.Unlock()
	return c.runErr
}

func (c *captureControl) tagCompletion(tag uint32, path string) string {
	mark := ""
	if c.runIncomplete.Load() {
		mark = " (run tracking incomplete)"
	}
	return fmt.Sprintf("tag %d finalized -> %s%s", tag, path, mark)
}
