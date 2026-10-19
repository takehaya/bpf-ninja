package main

import (
	"bytes"
	"sync/atomic"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// entry is a depth-0 entry record; nested gives one at depth d.
func entry(id uint64, b byte) capture.Packet { return nested(id, b, 0) }

func nested(id uint64, b byte, d uint32) capture.Packet {
	return capture.Packet{Mode: 0, PacketID: id, Action: d, Data: []byte{b, b}}
}

func decision(id uint64, verdict uint32) capture.Packet {
	return capture.Packet{Mode: 1, PacketID: id, Action: verdict}
}

// batch feeds pkts to the pairer as a reader feeds one batch: their
// bytes live in one buffer that is overwritten after Detach, as the ring
// is once the consumer position moves. It returns the kept packets,
// copied as the batch builder copies them.
func batch(p *eagerPairer, pkts []capture.Packet) []capture.Packet {
	var ring []byte
	for _, pk := range pkts {
		ring = append(ring, pk.Data...)
	}
	off := 0
	var out []capture.Packet
	for _, pk := range pkts {
		n := len(pk.Data)
		pk.Data = ring[off : off+n : off+n]
		off += n
		p.Record(0, pk, func(k capture.Packet) {
			k.Data = append([]byte(nil), k.Data...)
			out = append(out, k)
		})
	}
	p.Detach(0)
	for i := range ring {
		ring[i] = 'x'
	}
	return out
}

func ids(pkts []capture.Packet) []uint64 {
	var out []uint64
	for _, p := range pkts {
		out = append(out, p.PacketID)
	}
	return out
}

func TestEagerPairer(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	// Batch 1: 1 matched, 2 did not, 3 stays pending across the batch end.
	out := batch(p, []capture.Packet{entry(1, 'a'), decision(1, 1), entry(2, 'b'), entry(3, 'c')})
	if len(out) != 1 || out[0].PacketID != 1 || out[0].Action != 1 || out[0].Mode != 0 || !bytes.Equal(out[0].Data, []byte("aa")) {
		t.Fatalf("batch 1: %+v", out)
	}
	// Only 3 is still pending, so only 3 was copied out of the ring.
	if st := p.shards[0]; len(st.stack) != 1 || st.stack[0].owned == nil || st.stack[0].pkt.PacketID != 3 {
		t.Fatalf("pending after batch 1 = %+v", st.stack)
	}
	// Batch 2: 3's decision; 5's entry was lost, so its decision is an
	// orphan that must not take 4's bytes; 7 runs nested inside 6.
	out = batch(p, []capture.Packet{
		decision(3, 1), entry(4, 'd'), decision(5, 1),
		entry(6, 'f'), nested(7, 'g', 1), decision(7, 1), decision(6, 2),
	})
	if got := ids(out); len(got) != 3 || got[0] != 3 || got[1] != 7 || got[2] != 6 {
		t.Fatalf("batch 2 ids = %v, want [3 7 6]", got)
	}
	if !bytes.Equal(out[0].Data, []byte("cc")) || !bytes.Equal(out[1].Data, []byte("gg")) || !bytes.Equal(out[2].Data, []byte("ff")) || out[2].Action != 2 {
		t.Fatalf("batch 2: %+v", out)
	}
	// 2 and 4 never got a decision; the next depth-0 entry retired each.
	if n := len(p.shards[0].stack); n != 0 {
		t.Fatalf("pending = %d, want 0", n)
	}
	// 3's copy buffer went back for reuse after it paired.
	if n := len(p.shards[0].spare); n != 1 {
		t.Fatalf("spare = %d, want 1", n)
	}
	p.finish()
	if got := [3]uint64{p.paired.Load(), p.unmatched.Load(), p.orphan.Load()}; got != [3]uint64{4, 2, 1} {
		t.Fatalf("paired, unmatched, orphan = %v", got)
	}
	// 5 decisions + 2 unmatched entries.
	if discard.Load() != 7 {
		t.Fatalf("discard = %d, want 7", discard.Load())
	}
}

func TestEagerPairerCountsAtDetach(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	p.Record(0, entry(1, 'a'), func(capture.Packet) {})
	p.Record(0, decision(1, 1), func(capture.Packet) {})
	if p.paired.Load() != 0 || discard.Load() != 0 {
		t.Fatal("counts published before Detach")
	}
	p.Detach(0)
	if p.paired.Load() != 1 || discard.Load() != 1 {
		t.Fatalf("paired = %d discard = %d, want 1 and 1", p.paired.Load(), discard.Load())
	}
}

func TestEagerPairerNestedAcrossBatches(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	// The outer and inner entries end one batch; both decisions come in
	// the next, after the ring bytes were reused.
	if out := batch(p, []capture.Packet{entry(1, 'a'), nested(2, 'b', 1)}); len(out) != 0 {
		t.Fatalf("batch 1 kept %+v", out)
	}
	out := batch(p, []capture.Packet{decision(2, 3), decision(1, 1)})
	if got := ids(out); len(got) != 2 || got[0] != 2 || got[1] != 1 || !bytes.Equal(out[0].Data, []byte("bb")) || !bytes.Equal(out[1].Data, []byte("aa")) {
		t.Fatalf("out = %+v", out)
	}
}

func TestEagerPairerNestedMiss(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	// The inner invocation 2 misses the exit filter; the outer 1 matches.
	out := batch(p, []capture.Packet{entry(1, 'a'), nested(2, 'b', 1), decision(1, 1)})
	if got := ids(out); len(got) != 1 || got[0] != 1 || !bytes.Equal(out[0].Data, []byte("aa")) {
		t.Fatalf("out = %+v", out)
	}
	if p.unmatched.Load() != 1 {
		t.Fatalf("unmatched = %d, want 1", p.unmatched.Load())
	}
}

func TestEagerPairerSiblingMisses(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	// An outer invocation re-enters the target more times than there are
	// slots, one child after another, and every child misses the exit
	// filter: the children retire each other, never the active outer.
	in := []capture.Packet{entry(1, 'a')}
	for i := range eagerDepth + 3 {
		in = append(in, nested(uint64(i+2), 'z', 1))
	}
	in = append(in, decision(1, 1))
	out := batch(p, in)
	if got := ids(out); len(got) != 1 || got[0] != 1 || !bytes.Equal(out[0].Data, []byte("aa")) {
		t.Fatalf("out = %+v", out)
	}
	if p.unmatched.Load() != uint64(eagerDepth+3) || p.orphan.Load() != 0 {
		t.Fatalf("unmatched = %d orphan = %d, want %d and 0", p.unmatched.Load(), p.orphan.Load(), eagerDepth+3)
	}
}
