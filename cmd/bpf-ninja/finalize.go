package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/takehaya/bpf-ninja/internal/output"
)

// tagFinState is one tag's shared finalization state. Shard goroutines
// cache the pointer next to their writer and only touch the atomics on
// the write path.
type tagFinState struct {
	finalized atomic.Bool // stop sign: set by the finalizer; shards then drop the tag
	merged    atomic.Bool // set only after close+merge succeeded (the ack file exists)
	warned    atomic.Bool // one "dropping re-added tag" warning per tag
}

// tagFinalizer blocks a removed tag in the producer, waits for the kernel
// grace period and every shard's post-write watermark, then closes and merges
// its files. The ack is published only after successful persistence. A tag is
// single-use once its barrier begins; re-adding it cannot reopen production.
type tagFinalizer struct {
	basePath  string
	cfg       output.Config
	numShards int

	mu      sync.Mutex
	tags    map[uint32]*tagFinState     // every tag ever seen (traffic or set union)
	writers map[uint32][]*output.Writer // open shard writers per tag; index = shard
	begin   func(uint32) (func() (bool, error), error)
	pending map[uint32]func() (bool, error) // kernel barrier complete, waiting for shard acknowledgements
	failed  map[uint32]error                // terminal persistence failures: never publish an ack
	closing map[uint32]bool                 // stop sign raised: acknowledged tags awaiting successful merge
}

func newTagFinalizer(basePath string, cfg output.Config, numShards int) *tagFinalizer {
	return &tagFinalizer{
		basePath:  basePath,
		cfg:       cfg,
		numShards: numShards,
		tags:      map[uint32]*tagFinState{},
		writers:   map[uint32][]*output.Writer{},
		pending:   map[uint32]func() (bool, error){},
		closing:   map[uint32]bool{},
		failed:    map[uint32]error{},
	}
}

// stateFor returns the shared state for tag, creating it on first
// sight. Called once per (shard, tag); shards cache the result.
func (f *tagFinalizer) stateFor(tag uint32) *tagFinState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stateForLocked(tag)
}

func (f *tagFinalizer) stateForLocked(tag uint32) *tagFinState {
	st := f.tags[tag]
	if st == nil {
		st = &tagFinState{}
		f.tags[tag] = st
	}
	return st
}

// register records a shard's newly opened writer so the finalizer can
// flush and close it. Called from the shard goroutine on open.
func (f *tagFinalizer) register(tag uint32, shardIdx int, w *output.Writer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ws := f.writers[tag]
	if ws == nil {
		ws = make([]*output.Writer, f.numShards)
		f.writers[tag] = ws
	}
	ws[shardIdx] = w
}

// closeAll flushes and closes every writer still registered. Shutdown
// cleanup calls this instead of walking the shard maps when the
// finalizer is active: the registry is the ground truth for
// not-yet-closed writers, so a tag caught between its stop sign and its
// close+merge (e.g. SIGINT in that window) still gets flushed, and
// writers the finalizer already closed are not touched again.
func (f *tagFinalizer) closeAll() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for tag, ws := range f.writers {
		for _, w := range ws {
			if w != nil {
				if err := w.Close(); err != nil {
					f.failLocked(tag, err)
				}
			}
		}
		delete(f.writers, tag)
	}
	return f.errLocked()
}

// fail records a terminal output failure, distinct from a retryable merge error.
func (f *tagFinalizer) fail(tag uint32, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failLocked(tag, err)
}

func (f *tagFinalizer) failLocked(tag uint32, err error) {
	if err != nil && f.failed[tag] == nil {
		f.failed[tag] = fmt.Errorf("tag %d output failed: %w", tag, err)
	}
}

func (f *tagFinalizer) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.errLocked()
}

func (f *tagFinalizer) errLocked() error {
	var errs []error
	for _, err := range f.failed {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// deregister clears a shard's writer slot when the shard closes it
// itself (the capped path), so finalize never double-closes.
func (f *tagFinalizer) deregister(tag uint32, shardIdx int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ws := f.writers[tag]; ws != nil {
		ws[shardIdx] = nil
	}
}

// step starts barriers for absent tags and returns only acknowledged tags.
// No number of quiet polls can substitute for a reader acknowledgement.
func (f *tagFinalizer) step(union []uint32) []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	live := map[uint32]bool{}
	for _, tag := range union {
		live[tag] = true
		f.stateForLocked(tag)
	}
	for tag, st := range f.tags {
		if tag == 0 || st.finalized.Load() || f.failed[tag] != nil {
			continue
		}
		poll := f.pending[tag]
		if poll == nil {
			if live[tag] {
				continue
			}
			if f.begin == nil {
				f.failLocked(tag, fmt.Errorf("tag completion barrier not configured"))
				continue
			}
			var err error
			poll, err = f.begin(tag)
			if err != nil {
				f.failLocked(tag, err)
				continue
			}
			f.pending[tag] = poll
		}
		ready, err := poll()
		if err != nil {
			f.failLocked(tag, err)
			continue
		}
		if ready {
			st.finalized.Store(true)
			delete(f.pending, tag)
			f.closing[tag] = true
		}
	}
	var done []uint32
	for tag := range f.closing {
		if f.failed[tag] == nil {
			done = append(done, tag)
		}
	}
	slices.Sort(done)
	return done
}

// markMerged records a successful close+merge; the tag leaves the retry
// set and the shutdown merge will skip it.
func (f *tagFinalizer) markMerged(tag uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed[tag] != nil {
		return
	}
	f.stateForLocked(tag).merged.Store(true)
	delete(f.closing, tag)
}

// isMerged reports whether this run successfully produced the tag's
// ack file (close+merge completed).
func (f *tagFinalizer) isMerged(tag uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.tags[tag]
	return st != nil && st.merged.Load()
}

// mergedTags returns the tags whose ack file was successfully produced
// during this run, for the shutdown merge to skip: a consumed ack must
// not be recreated after the collector took it. Tags that quiesced but
// whose merge kept failing are NOT skipped — the shutdown merge is
// their last chance to produce the file.
func (f *tagFinalizer) mergedTags() map[uint32]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	done := map[uint32]bool{}
	for tag, st := range f.tags {
		if st.merged.Load() {
			done[tag] = true
		}
	}
	return done
}

// finalize runs only after step has acknowledged every shard. Writer errors
// are terminal; merge errors retain the immutable shards for a later retry.
func (f *tagFinalizer) finalize(tag uint32) error {
	f.mu.Lock()
	if err := f.failed[tag]; err != nil {
		f.mu.Unlock()
		return err
	}
	if st := f.tags[tag]; st != nil && st.merged.Load() {
		f.mu.Unlock()
		return nil
	}
	ws := f.writers[tag]
	delete(f.writers, tag)
	f.mu.Unlock()

	var errs []error
	for _, w := range ws {
		if w != nil {
			if err := w.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		err := fmt.Errorf("closing tag %d shard writers: %w", tag, errors.Join(errs...))
		f.fail(tag, err)
		return err
	}
	if err := output.MergeOneTagShards(f.basePath, f.numShards, tag, f.cfg); err != nil {
		return fmt.Errorf("finalizing tag %d (will retry): %v", tag, err)
	}
	f.markMerged(tag)
	return nil
}

// warnDropped emits the once-per-tag notice that records for a
// finalized tag are being dropped (a re-added entry after finalize).
func warnDropped(tag uint32, st *tagFinState) {
	if st.warned.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "warning: tag %d was finalized; dropping records for its re-added set entry (--finalize-on-del tags are single-use)\n", tag)
	}
}
