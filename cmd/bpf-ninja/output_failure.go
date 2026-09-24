package main

import "sync/atomic"

// outputFailure wakes the coordinator on the first failed write. Shard readers
// may keep draining until stopped, so retain the error independently of them.
type outputFailure struct {
	first atomic.Pointer[error]
	done  chan struct{}
}

func newOutputFailure() *outputFailure { return &outputFailure{done: make(chan struct{})} }

func (f *outputFailure) record(err error) {
	if err != nil && f.first.CompareAndSwap(nil, &err) {
		close(f.done)
	}
}

func (f *outputFailure) err() error {
	if p := f.first.Load(); p != nil {
		return *p
	}
	return nil
}
