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

func TestEagerPairer(t *testing.T) {
	var discard atomic.Uint64
	p := newEagerPairer(1, &discard)
	// Batch 1: A matched, B did not, C stays pending across the batch end.
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
	// Batch 2: C's decision, then D pending again, whose entry is lost
	// so E's decision is an orphan that must not take D's bytes.
	out = p.pair(0, []capture.Packet{decision(3, 1), entry(4, 'd'), decision(5, 1)})
	if len(out) != 1 || out[0].PacketID != 3 || !bytes.Equal(out[0].Data, []byte("cc")) {
		t.Fatalf("batch 2: %+v", out)
	}
	if got := [3]uint64{p.paired.Load(), p.unmatched.Load(), p.orphan.Load()}; got != [3]uint64{2, 2, 1} {
		t.Fatalf("paired, unmatched, orphan = %v", got)
	}
	// 3 decisions + 2 unmatched entries; D is not pending (its slot was
	// cleared by the orphan decision).
	p.finish()
	if discard.Load() != 5 {
		t.Fatalf("discard = %d, want 5", discard.Load())
	}
}
