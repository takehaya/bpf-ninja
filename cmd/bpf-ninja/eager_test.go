package main

import (
	"bytes"
	"sync/atomic"
	"testing"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

func entry(id uint64, b byte) capture.Packet {
	return capture.Packet{Mode: 0, PacketID: id, Data: []byte{b, b}}
}

func decision(id uint64, verdict uint32) capture.Packet {
	return capture.Packet{Mode: 1, PacketID: id, Action: verdict}
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
	b1 := []capture.Packet{entry(1, 'a'), decision(1, 1), entry(2, 'b'), entry(3, 'c')}
	out := p.pair(0, b1)
	if len(out) != 1 || out[0].PacketID != 1 || out[0].Action != 1 || out[0].Mode != 0 || !bytes.Equal(out[0].Data, []byte("aa")) {
		t.Fatalf("batch 1: %+v", out)
	}
	// The reader recycles its arena after the sink returns.
	for i := range b1 {
		for j := range b1[i].Data {
			b1[i].Data[j] = 'x'
		}
	}
	// Batch 2: 3's decision; 5's entry was lost, so its decision is an
	// orphan that must not take 4's bytes; 7 runs nested inside 6.
	out = p.pair(0, []capture.Packet{
		decision(3, 1), entry(4, 'd'), decision(5, 1),
		entry(6, 'f'), entry(7, 'g'), decision(7, 1), decision(6, 2),
	})
	if got := ids(out); len(got) != 3 || got[0] != 3 || got[1] != 7 || got[2] != 6 {
		t.Fatalf("batch 2 ids = %v, want [3 7 6]", got)
	}
	if !bytes.Equal(out[0].Data, []byte("cc")) || !bytes.Equal(out[2].Data, []byte("ff")) || out[2].Action != 2 {
		t.Fatalf("batch 2: %+v", out)
	}
	// 2 and 4 never got a decision.
	p.finish()
	if got := [3]uint64{p.paired.Load(), p.unmatched.Load(), p.orphan.Load()}; got != [3]uint64{4, 2, 1} {
		t.Fatalf("paired, unmatched, orphan = %v", got)
	}
	// 5 decisions + 2 unmatched entries.
	if discard.Load() != 7 {
		t.Fatalf("discard = %d, want 7", discard.Load())
	}
}

func TestEagerPairerNestedMiss(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	// The inner invocation 2 misses the exit filter; the outer 1 matches.
	out := p.pair(0, []capture.Packet{entry(1, 'a'), entry(2, 'b'), decision(1, 1)})
	if got := ids(out); len(got) != 1 || got[0] != 1 || !bytes.Equal(out[0].Data, []byte("aa")) {
		t.Fatalf("out = %+v", out)
	}
	if p.unmatched.Load() != 1 {
		t.Fatalf("unmatched = %d, want 1", p.unmatched.Load())
	}
}

func TestEagerPairerBound(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	var in []capture.Packet
	for i := range eagerDepth + 3 {
		in = append(in, entry(uint64(i+1), 'z'))
	}
	p.pair(0, in)
	if n := len(p.shards[0].stack); n != eagerDepth {
		t.Fatalf("pending = %d, want %d", n, eagerDepth)
	}
	if p.unmatched.Load() != 3 {
		t.Fatalf("unmatched = %d, want 3", p.unmatched.Load())
	}
}
