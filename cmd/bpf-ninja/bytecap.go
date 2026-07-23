package main

import (
	"sync"
	"sync/atomic"

	"github.com/takehaya/bpf-ninja/internal/setmap"
)

// tagCounter accumulates one tag's output bytes across every shard.
// Shards cache the pointer next to their writer, so the write path only
// touches the two atomics — never the byteCaps map.
type tagCounter struct {
	bytes  atomic.Uint64
	capped atomic.Bool
}

// byteCaps is the shared state behind --max-bytes-per-tag / --max-bytes.
// Limits are fixed at startup; counters are written by shard goroutines
// and read by the pumpShards poll loop. A limit of 0 means "off".
//
// Accounting is deliberately approximate: bytes are added per same-tag
// run after a successful WriteBatch, so a tag can overshoot its cap by
// at most one ringbuf batch per shard (issue #86 tolerates this).
type byteCaps struct {
	perTagLimit uint64
	totalLimit  uint64
	total       atomic.Uint64

	mu   sync.Mutex // guards tags inserts; lookups after the fast path miss
	tags map[uint32]*tagCounter
}

// newByteCaps returns nil when both limits are 0 so callers can nil-guard
// the hot path exactly like the count > 0 pattern.
func newByteCaps(perTag, total uint64) *byteCaps {
	if perTag == 0 && total == 0 {
		return nil
	}
	return &byteCaps{
		perTagLimit: perTag,
		totalLimit:  total,
		tags:        map[uint32]*tagCounter{},
	}
}

// counterFor returns the shared counter for tag, creating it on first
// sight. Called once per (shard, tag) — the shard caches the result.
func (c *byteCaps) counterFor(tag uint32) *tagCounter {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctr := c.tags[tag]
	if ctr == nil {
		ctr = &tagCounter{}
		c.tags[tag] = ctr
	}
	return ctr
}

// addTag adds n output bytes to ctr and returns true exactly once, on
// the transition to capped (so the caller can log it once).
func (c *byteCaps) addTag(ctr *tagCounter, n uint64) bool {
	if ctr.bytes.Add(n) >= c.perTagLimit {
		return ctr.capped.CompareAndSwap(false, true)
	}
	return false
}

// addTotal adds n bytes to the aggregate counter and reports whether the
// --max-bytes limit has been reached (always false when that limit is
// off).
func (c *byteCaps) addTotal(n uint64) bool {
	return c.total.Add(n) >= c.totalLimit && c.totalLimit > 0
}

func (c *byteCaps) totalReached() bool {
	return c.totalLimit > 0 && c.total.Load() >= c.totalLimit
}

// anyCapped reports whether at least one tag has reached the per-tag
// cap; the poll loop uses it to skip set-map iteration until then.
func (c *byteCaps) anyCapped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ctr := range c.tags {
		if ctr.capped.Load() {
			return true
		}
	}
	return false
}

// unionSetTags collects the tags of every entry currently present in
// the given sets. --exit-when-capped compares this live view against
// the capped counters, so entries added or removed at runtime are
// honored. Tag 0 is dropped: it is indistinguishable from unmatched
// traffic on the packet side, so it never participates in the exit
// decision (as documented).
func unionSetTags(sets []*setmap.Set) ([]uint32, error) {
	seen := map[uint32]bool{}
	var tags []uint32
	for _, s := range sets {
		t, err := s.Def.Tags()
		if err != nil {
			return nil, err
		}
		for _, tag := range t {
			if tag != 0 && !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	return tags, nil
}

// allCapped reports whether every tag in tags has reached the per-tag
// cap. An empty list or a tag with no traffic yet (no counter) means
// "not all capped" — the capture keeps running.
func (c *byteCaps) allCapped(tags []uint32) bool {
	if len(tags) == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, tag := range tags {
		ctr := c.tags[tag]
		if ctr == nil || !ctr.capped.Load() {
			return false
		}
	}
	return true
}
