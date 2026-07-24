package main

import (
	"sync"
	"sync/atomic"

	"github.com/takehaya/bpf-ninja/internal/setmap"
)

// tagCounter accumulates one tag's output bytes across every shard.
// Shards cache the pointer next to their writer, so the write path only
// touches the atomics — never the byteCaps map.
type tagCounter struct {
	bytes  atomic.Uint64
	limit  atomic.Uint64 // per-entry cap from the set value (0 = uncapped); refreshed each poll cycle
	capped atomic.Bool
}

// byteCaps is the shared state behind per-entry byte caps (`set add ...
// max-bytes=N`) and the aggregate --max-bytes. The aggregate limit is
// fixed at startup; per-tag limits come from the set entries and are
// refreshed from the live maps each poll cycle (~1s), so caps added or
// raised at runtime take effect. capped is one-way: raising a limit
// after a tag capped does not resume it.
//
// The record only carries a u32 tag, so a cap is effectively per TAG:
// entries sharing a tag share one budget (last writer wins on the
// limit), matching the last-match-wins tag semantics.
//
// Accounting is deliberately approximate: bytes are added per same-tag
// run after a successful WriteBatch, so a tag can overshoot its cap by
// at most one ringbuf batch per shard (issue #86 tolerates this).
type byteCaps struct {
	perTag     bool // split-by-tag with sets: per-entry caps may apply
	totalLimit uint64
	total      atomic.Uint64

	mu   sync.Mutex // guards all tags map access (insert, lookup, iteration)
	tags map[uint32]*tagCounter
}

// newByteCaps returns nil when nothing can cap so callers can nil-guard
// the hot path exactly like the count > 0 pattern.
func newByteCaps(perTag bool, total uint64) *byteCaps {
	if !perTag && total == 0 {
		return nil
	}
	return &byteCaps{
		perTag:     perTag,
		totalLimit: total,
		tags:       map[uint32]*tagCounter{},
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

// effectiveLimits reduces a snapshot to one deterministic limit per
// tag. Map iteration order is unstable, so entries sharing a tag must
// not race on "last seen wins": an uncapped entry (0) makes the whole
// tag uncapped (0 = no limit, the most permissive), otherwise the
// largest cap wins. Tag 0 is excluded.
func effectiveLimits(infos []setmap.TagInfo) map[uint32]uint64 {
	limits := map[uint32]uint64{}
	for _, in := range infos {
		if in.Tag == 0 {
			continue
		}
		cur, seen := limits[in.Tag]
		switch {
		case !seen:
			limits[in.Tag] = in.MaxBytes
		case cur == 0 || in.MaxBytes == 0:
			limits[in.Tag] = 0
		case in.MaxBytes > cur:
			limits[in.Tag] = in.MaxBytes
		}
	}
	return limits
}

// refreshLimits pulls the snapshot's effective per-tag caps into the
// tag counters (0 = uncapped, including legacy layouts).
func (c *byteCaps) refreshLimits(infos []setmap.TagInfo) {
	for tag, lim := range effectiveLimits(infos) {
		c.counterFor(tag).limit.Store(lim)
	}
}

// addTag adds n output bytes to ctr and returns true exactly once, on
// the transition to capped (so the caller can log it once).
func (c *byteCaps) addTag(ctr *tagCounter, n uint64) bool {
	total := ctr.bytes.Add(n)
	if lim := ctr.limit.Load(); lim > 0 && total >= lim {
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

// cappedTags returns every tag whose cap has been reached, for the poll
// loop to park (state=capped) and for the exit decision.
func (c *byteCaps) cappedTags() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var tags []uint32
	for tag, ctr := range c.tags {
		if ctr.capped.Load() {
			tags = append(tags, tag)
		}
	}
	return tags
}

// anyCapped reports whether at least one tag has reached its cap; the
// poll loop uses it to keep the quiet path cheap.
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

// allCapped reports whether every entry that HAS a cap has reached it
// (either its counter capped, or the entry already parked in a
// non-active state). Uncapped entries and tag 0 never participate; with
// no participating entry at all the answer is false — the capture keeps
// running.
func (c *byteCaps) allCapped(infos []setmap.TagInfo) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	participating := false
	for _, in := range infos {
		if in.Tag == 0 || in.MaxBytes == 0 {
			continue
		}
		participating = true
		if in.State != setmap.StateActive {
			continue // already parked (capped/finalized)
		}
		ctr := c.tags[in.Tag]
		if ctr == nil || !ctr.capped.Load() {
			return false
		}
	}
	return participating
}

// unionTagInfos collects the value of every entry currently present in
// the given sets — the poll loop's single ~1s snapshot feeding limit
// refresh, the exit decision, and the finalizer's active-tag union.
func unionTagInfos(sets []*setmap.Set) ([]setmap.TagInfo, error) {
	var infos []setmap.TagInfo
	for _, s := range sets {
		in, err := s.Def.TagInfos()
		if err != nil {
			return nil, err
		}
		infos = append(infos, in...)
	}
	return infos, nil
}

// activeTags reduces a TagInfo snapshot to the distinct non-zero tags
// with at least one ACTIVE entry — the union the finalizer's quiesce
// logic runs against (a parked entry is equivalent to a deleted one).
func activeTags(infos []setmap.TagInfo) []uint32 {
	seen := map[uint32]bool{}
	var tags []uint32
	for _, in := range infos {
		if in.Tag != 0 && in.State == setmap.StateActive && !seen[in.Tag] {
			seen[in.Tag] = true
			tags = append(tags, in.Tag)
		}
	}
	return tags
}
