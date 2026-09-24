package main

import "github.com/takehaya/bpf-ninja/internal/capture"

// One control belongs to one probe/capture, including all its shards.
type captureControl struct {
	quiesce func() error
	stats   *capture.SessionStats
}

func controlOrNew(cs []*captureControl) *captureControl {
	if len(cs) > 0 {
		return cs[0]
	}
	return &captureControl{}
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
