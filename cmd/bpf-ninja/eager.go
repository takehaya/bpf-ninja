package main

import (
	"sync/atomic"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/program"
)

// eagerPairer is the userspace half of the experimental --emit eager
// baseline: the kernel exports every entry image at once, carrying its
// nesting depth on this CPU in the action field, and a metadata-only
// decision record when the exit filter matches. Each shard is one CPU's
// ring, so records arrive in execution order, and nesting is LIFO. The
// pairer keeps a stack of unanswered entries per shard. An entry at depth
// d retires every pending entry at depth >= d (those invocations have
// finished without a decision); a decision takes the entry with its
// packet id and retires the entries pushed after it.
//
// It runs as the reader's record filter, on records still in the ring, so
// only a paired entry is copied into the batch. An entry still pending
// when the reader releases the ring is copied out; nesting bounds those.
type eagerPairer struct {
	shards                    []eagerShard
	paired, unmatched, orphan atomic.Uint64
	// discard receives every record the pairer drops: all decision records
	// and the entries that never met their decision.
	discard *atomic.Uint64
}

// eagerDepth bounds the pending entries per shard: one per possible
// nesting depth of the gated hold. Depth retirement keeps the stack
// within it; the bound only guards against a malformed depth.
var eagerDepth = program.MaxHoldSlots

type eagerShard struct {
	stack []eagerPending
	// spare holds copy buffers free for reuse.
	spare [][]byte
	// counts since the last Detach, published there
	paired, unmatched, orphan, discard uint64
}

type eagerPending struct {
	pkt   capture.Packet
	depth uint32
	owned []byte // non-nil once pkt.Data was copied out of the ring
}

func newEagerPairer(shards int, discard *atomic.Uint64) *eagerPairer {
	return &eagerPairer{shards: make([]eagerShard, shards), discard: discard}
}

// drop retires an entry that never met its decision.
func (st *eagerShard) drop(e eagerPending) {
	st.unmatched++
	st.discard++
	if e.owned != nil {
		st.spare = append(st.spare, e.owned)
	}
}

// Record pairs one record. keep copies the paired entry, so its buffer is
// free again once keep returns.
func (p *eagerPairer) Record(shard int, pk capture.Packet, keep func(capture.Packet)) {
	st := &p.shards[shard]
	if pk.Mode == 0 {
		d := pk.Action
		for len(st.stack) > 0 && st.stack[len(st.stack)-1].depth >= d {
			st.drop(st.stack[len(st.stack)-1])
			st.stack = st.stack[:len(st.stack)-1]
		}
		if len(st.stack) == eagerDepth {
			st.drop(st.stack[0])
			st.stack = append(st.stack[:0], st.stack[1:]...)
		}
		pk.Action = 0
		st.stack = append(st.stack, eagerPending{pkt: pk, depth: d})
		return
	}
	st.discard++
	j := len(st.stack) - 1
	for j >= 0 && st.stack[j].pkt.PacketID != pk.PacketID {
		j--
	}
	if j < 0 {
		st.orphan++
		return
	}
	for _, e := range st.stack[j+1:] {
		st.drop(e)
	}
	e := st.stack[j]
	st.stack = st.stack[:j]
	ent := e.pkt
	ent.Action = pk.Action
	keep(ent)
	if e.owned != nil {
		st.spare = append(st.spare, e.owned)
	}
	st.paired++
}

// Detach copies the pending entries out of the ring before the reader
// releases it, and publishes the counts.
func (p *eagerPairer) Detach(shard int) {
	st := &p.shards[shard]
	for k := range st.stack {
		e := &st.stack[k]
		if e.owned != nil {
			continue
		}
		var buf []byte
		if n := len(st.spare); n > 0 {
			buf, st.spare = st.spare[n-1][:0], st.spare[:n-1]
		}
		e.owned = append(buf, e.pkt.Data...)
		e.pkt.Data = e.owned
	}
	p.paired.Add(st.paired)
	p.unmatched.Add(st.unmatched)
	p.orphan.Add(st.orphan)
	p.discard.Add(st.discard)
	st.paired, st.unmatched, st.orphan, st.discard = 0, 0, 0, 0
}

// finish drops the entries still waiting for a decision once every shard
// has drained.
func (p *eagerPairer) finish() {
	for i := range p.shards {
		n := uint64(len(p.shards[i].stack))
		p.shards[i].stack = nil
		p.unmatched.Add(n)
		p.discard.Add(n)
	}
}
