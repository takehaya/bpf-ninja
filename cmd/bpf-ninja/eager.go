package main

import (
	"sync/atomic"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// eagerPairer is the userspace half of the experimental --emit eager
// baseline: the kernel exports every entry image at once and a
// metadata-only decision record when the exit filter matches. Each shard
// is one CPU's ring, so a decision follows its own entry in order; the
// pairer keeps the last unanswered entry per shard and writes it, stamped
// with the decision's verdict, when the decision with the same packet id
// arrives. A second entry before a decision means the first did not match
// at exit (or its decision was lost).
type eagerPairer struct {
	shards                    []eagerShard
	paired, unmatched, orphan atomic.Uint64
	// discard receives every record the pairer drops: all decision records
	// and the entries that never met their decision.
	discard *atomic.Uint64
}

type eagerShard struct {
	pkt  capture.Packet
	ok   bool
	bufs [2][]byte
	cur  int
}

func newEagerPairer(shards int, discard *atomic.Uint64) *eagerPairer {
	return &eagerPairer{shards: make([]eagerShard, shards), discard: discard}
}

// finish drops the entries still waiting for a decision once every shard
// has drained.
func (p *eagerPairer) finish() {
	for i := range p.shards {
		if p.shards[i].ok {
			p.shards[i].ok = false
			p.unmatched.Add(1)
			p.discard.Add(1)
		}
	}
}

// pair filters one shard batch in place and returns the entry images to
// write. pkts is owned by the reader until the sink returns; an entry left
// pending at the end of the batch is copied out.
func (p *eagerPairer) pair(shard int, pkts []capture.Packet) []capture.Packet {
	st := &p.shards[shard]
	out := pkts[:0]
	pend := -1
	var paired, unmatched, orphan, decisions uint64
	for i := range pkts {
		pk := pkts[i]
		if pk.Mode == 0 {
			if pend >= 0 || st.ok {
				unmatched++
			}
			st.ok, pend = false, i
			continue
		}
		decisions++
		var e *capture.Packet
		switch {
		case pend >= 0:
			e = &pkts[pend]
		case st.ok:
			e = &st.pkt
		}
		if e != nil && e.PacketID == pk.PacketID {
			ent := *e
			ent.Action = pk.Action
			out = append(out, ent)
			paired++
		} else {
			if e != nil {
				unmatched++
			}
			orphan++
		}
		st.ok, pend = false, -1
	}
	if pend >= 0 {
		// Alternate buffers: an entry written from st.pkt in this batch
		// still points at the other one until the sink returns.
		st.cur ^= 1
		st.bufs[st.cur] = append(st.bufs[st.cur][:0], pkts[pend].Data...)
		st.pkt = pkts[pend]
		st.pkt.Data = st.bufs[st.cur]
		st.ok = true
	}
	p.paired.Add(paired)
	p.unmatched.Add(unmatched)
	p.orphan.Add(orphan)
	p.discard.Add(decisions + unmatched)
	return out
}
