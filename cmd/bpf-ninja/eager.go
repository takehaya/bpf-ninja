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
	// spare holds buffers free for reuse; released holds buffers whose
	// entries were handed to the sink in the current batch.
	spare, released [][]byte
}

type eagerPending struct {
	pkt   capture.Packet
	depth uint32
	owned []byte // non-nil once pkt.Data was copied out of the batch arena
}

func newEagerPairer(shards int, discard *atomic.Uint64) *eagerPairer {
	return &eagerPairer{shards: make([]eagerShard, shards), discard: discard}
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

// pair filters one shard batch in place and returns the entry images to
// write. pkts is owned by the reader until the sink returns, so entries
// still pending at the end of the batch are copied out.
func (p *eagerPairer) pair(shard int, pkts []capture.Packet) []capture.Packet {
	st := &p.shards[shard]
	// The sink has consumed the previous batch.
	st.spare = append(st.spare, st.released...)
	st.released = st.released[:0]
	out := pkts[:0]
	var paired, unmatched, orphan, decisions uint64
	drop := func(e eagerPending) {
		unmatched++
		if e.owned != nil {
			st.spare = append(st.spare, e.owned)
		}
	}
	for i := range pkts {
		pk := pkts[i]
		if pk.Mode == 0 {
			d := pk.Action
			for len(st.stack) > 0 && st.stack[len(st.stack)-1].depth >= d {
				drop(st.stack[len(st.stack)-1])
				st.stack = st.stack[:len(st.stack)-1]
			}
			if len(st.stack) == eagerDepth {
				drop(st.stack[0])
				st.stack = append(st.stack[:0], st.stack[1:]...)
			}
			pk.Action = 0
			st.stack = append(st.stack, eagerPending{pkt: pk, depth: d})
			continue
		}
		decisions++
		j := len(st.stack) - 1
		for j >= 0 && st.stack[j].pkt.PacketID != pk.PacketID {
			j--
		}
		if j < 0 {
			orphan++
			continue
		}
		for _, e := range st.stack[j+1:] {
			drop(e)
		}
		e := st.stack[j]
		st.stack = st.stack[:j]
		ent := e.pkt
		ent.Action = pk.Action
		// out's write index never passes i, and the entry was read before
		// this slot is overwritten.
		out = append(out, ent)
		if e.owned != nil {
			st.released = append(st.released, e.owned)
		}
		paired++
	}
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
	p.paired.Add(paired)
	p.unmatched.Add(unmatched)
	p.orphan.Add(orphan)
	p.discard.Add(decisions + unmatched)
	return out
}
