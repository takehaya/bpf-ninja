package main

import (
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
	activity  atomic.Uint64 // bumped once per written same-tag run
	finalized atomic.Bool   // set by the finalizer; shards then drop the tag
	warned    atomic.Bool   // one "dropping re-added tag" warning per tag
}

// tagFinalizer implements --finalize-on-del: when a tag's last set entry
// is removed and a full poll cycle passes with no records for it, the
// tag's shard writers are flushed and closed and its shards are merged
// into <stem>.<tag><ext> while the capture keeps running. The merged
// file appearing is the caller's completion ack.
//
// Quiescence needs two consecutive poll cycles because a record read
// from the ringbuf just before `set del` may still be in flight during
// the first cycle; a second cycle with unchanged activity proves the
// backlog for that tag has drained (the kernel stopped matching at del).
type tagFinalizer struct {
	basePath  string
	cfg       output.Config
	numShards int

	mu      sync.Mutex
	tags    map[uint32]*tagFinState        // every tag ever seen (traffic or set union)
	writers map[uint32][]*output.Writer    // open shard writers per tag; index = shard
	pending map[uint32]uint64              // finalize candidates: tag -> activity at first eligible cycle
}

func newTagFinalizer(basePath string, cfg output.Config, numShards int) *tagFinalizer {
	return &tagFinalizer{
		basePath:  basePath,
		cfg:       cfg,
		numShards: numShards,
		tags:      map[uint32]*tagFinState{},
		writers:   map[uint32][]*output.Writer{},
		pending:   map[uint32]uint64{},
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

// deregister clears a shard's writer slot when the shard closes it
// itself (the capped path), so finalize never double-closes.
func (f *tagFinalizer) deregister(tag uint32, shardIdx int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ws := f.writers[tag]; ws != nil {
		ws[shardIdx] = nil
	}
}

// step runs one poll cycle against the live set-map tag union and
// returns the tags that just became quiesced, in ascending order. A tag
// is quiesced when it is absent from the union for two consecutive
// cycles with unchanged activity. Tags reappearing in the union (or
// still receiving records) drop out of the candidate set. Union-seen
// tags are registered too, so a tag whose entry is removed before any
// traffic still finalizes (to an empty pcap-ng).
func (f *tagFinalizer) step(union []uint32) []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()

	live := map[uint32]bool{}
	for _, tag := range union {
		live[tag] = true
		f.stateForLocked(tag)
	}

	var done []uint32
	for tag, st := range f.tags {
		if tag == 0 || st.finalized.Load() || live[tag] {
			delete(f.pending, tag)
			continue
		}
		act := st.activity.Load()
		prev, wasPending := f.pending[tag]
		if wasPending && prev == act {
			st.finalized.Store(true)
			delete(f.pending, tag)
			done = append(done, tag)
			continue
		}
		f.pending[tag] = act
	}
	slices.Sort(done)
	return done
}

// finalizedTags returns the tags finalized during this run, for the
// shutdown merge to skip: their per-tag file is a consumed completion
// ack and must not be recreated after the collector took it.
func (f *tagFinalizer) finalizedTags() map[uint32]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	done := map[uint32]bool{}
	for tag, st := range f.tags {
		if st.finalized.Load() {
			done[tag] = true
		}
	}
	return done
}

// finalize flushes and closes the tag's remaining shard writers, then
// merges its shards into the per-tag file (atomic temp + rename). Safe
// to run from the poll goroutine: the tag is quiesced, so no shard will
// touch these writers again, and shards drop any re-added tag's records
// after the finalized flag flipped in step.
func (f *tagFinalizer) finalize(tag uint32) error {
	f.mu.Lock()
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
	if err := output.MergeOneTagShards(f.basePath, f.numShards, tag, f.cfg); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("finalizing tag %d: %v", tag, errs)
	}
	return nil
}

// warnDropped emits the once-per-tag notice that records for a
// finalized tag are being dropped (a re-added entry after finalize).
func warnDropped(tag uint32, st *tagFinState) {
	if st.warned.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr, "warning: tag %d was finalized; dropping records for its re-added set entry (--finalize-on-del tags are single-use)\n", tag)
	}
}
