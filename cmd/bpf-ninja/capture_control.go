package main

import "sync/atomic"

import "github.com/takehaya/bpf-ninja/internal/capture"

// One control belongs to one probe/capture, including all its shards.
type captureControl struct {
	written     atomic.Uint64
	limited     atomic.Uint64
	nullRecords atomic.Uint64
	quiesce     func() error
	blockTag    func(uint32) error
	barrier     func() func() (bool, error)
	stats       *capture.SessionStats
	outputErr   *outputFailure
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
