package capture

import (
	"encoding/binary"
	"testing"
)

func TestParsePacket(t *testing.T) {
	// metadata (16B): kernel_ts=12345, action=2 (PASS), mode=1 (exit), pad=0, caplen=4
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}

	raw := make([]byte, MetadataSize+len(pktData))
	binary.NativeEndian.PutUint64(raw[0:8], 12345)                  // kernel_ts_ns
	binary.NativeEndian.PutUint32(raw[8:12], 2)                     // action = XDP_PASS
	raw[12] = 1                                                     // mode = exit
	raw[13] = 0                                                     // pad
	binary.NativeEndian.PutUint16(raw[14:16], uint16(len(pktData))) // caplen
	copy(raw[MetadataSize:], pktData)

	pkt, err := ParseRawSample(raw)
	if err != nil {
		t.Fatalf("ParseRawSample failed: %v", err)
	}

	if pkt.Action != 2 {
		t.Errorf("Action = %d, want 2", pkt.Action)
	}
	if pkt.Mode != 1 {
		t.Errorf("Mode = %d, want 1", pkt.Mode)
	}
	if pkt.CapLen != uint16(len(pktData)) {
		t.Errorf("CapLen = %d, want %d", pkt.CapLen, len(pktData))
	}
	if len(pkt.Data) != len(pktData) {
		t.Errorf("Data length = %d, want %d", len(pkt.Data), len(pktData))
	}
	if pkt.Data[0] != 0xde || pkt.Data[3] != 0xef {
		t.Errorf("Data = %x, want deadbeef", pkt.Data)
	}
}

// TestParsePacketCaplenTrim verifies caplen-based trimming when the
// raw record carries trailing slack (the bpf_ringbuf_reserve+submit
// path always submits a full reservation, so caplen < len(raw)-16).
func TestParsePacketCaplenTrim(t *testing.T) {
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}
	const slack = 16
	raw := make([]byte, MetadataSize+len(pktData)+slack)
	binary.NativeEndian.PutUint64(raw[0:8], 0)
	binary.NativeEndian.PutUint32(raw[8:12], 0)
	raw[12] = 0
	binary.NativeEndian.PutUint16(raw[14:16], uint16(len(pktData)))
	copy(raw[MetadataSize:], pktData)
	// raw[MetadataSize+len(pktData):] is trailing slack — should be ignored.

	pkt, err := ParseRawSample(raw)
	if err != nil {
		t.Fatalf("ParseRawSample failed: %v", err)
	}
	if len(pkt.Data) != len(pktData) {
		t.Errorf("Data length = %d, want %d (slack should be trimmed)", len(pkt.Data), len(pktData))
	}
}

func TestParsePacketTooShort(t *testing.T) {
	raw := make([]byte, 3) // less than MetadataSize (16)
	_, err := ParseRawSample(raw)
	if err == nil {
		t.Fatal("expected error for short sample, got nil")
	}
}

func TestParsePacketMetadataOnly(t *testing.T) {
	// metadata only, no packet data (edge case)
	raw := make([]byte, MetadataSize)
	binary.NativeEndian.PutUint64(raw[0:8], 0)  // kernel_ts = 0
	binary.NativeEndian.PutUint32(raw[8:12], 0) // action = 0
	raw[12] = 0                                 // mode = entry

	pkt, err := ParseRawSample(raw)
	if err != nil {
		t.Fatalf("ParseRawSample failed: %v", err)
	}
	if len(pkt.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(pkt.Data))
	}
}

// makeRecord builds a ringbuf record with the given caplen payload
// filled with byte value fill, mirroring the BPF reserve+submit format.
func makeRecord(buf []byte, fill byte, caplen int) []byte {
	raw := buf[:MetadataSize+caplen]
	binary.NativeEndian.PutUint16(raw[OffsetCapLen:OffsetCapLen+2], uint16(caplen))
	for i := range caplen {
		raw[MetadataSize+i] = fill
	}
	return raw
}

// TestBatchBuilderOwnsPayload is the regression test for the slice-
// aliasing bug: ParseRawSample returns a Packet whose Data aliases the
// source record buffer, which the reader reuses across reads. Before the
// fix, a batch flushed to sink handed every Packet the LAST record's
// bytes. batchBuilder must copy each payload so the flushed batch
// preserves per-packet content even when the source buffer is mutated
// after add().
func TestBatchBuilderOwnsPayload(t *testing.T) {
	var got [][]byte
	sink := func(_ int, pkts []Packet) error {
		for _, p := range pkts {
			cp := make([]byte, len(p.Data))
			copy(cp, p.Data)
			got = append(got, cp)
		}
		return nil
	}

	bb := newBatchBuilder(0, sink)

	// One reused source buffer, exactly as the reader reuses
	// ringbuf.Record.RawSample / the mmap ring across reads.
	src := make([]byte, MetadataSize+64)
	fills := []byte{0xAA, 0xBB, 0xCC}
	for _, f := range fills {
		raw := makeRecord(src, f, 8)
		pkt, err := ParseRawSample(raw)
		if err != nil {
			t.Fatalf("ParseRawSample: %v", err)
		}
		bb.add(pkt)
		// Scribble over the shared buffer to simulate the next read
		// overwriting the previous record in place.
		for i := range src {
			src[i] = 0
		}
	}
	bb.flush()

	if len(got) != len(fills) {
		t.Fatalf("got %d packets, want %d", len(got), len(fills))
	}
	for i, f := range fills {
		for j, b := range got[i] {
			if b != f {
				t.Fatalf("packet %d byte %d = %#x, want %#x (aliasing regression)", i, j, b, f)
			}
		}
	}
}

// TestBatchBuilderArenaOverflow feeds more total payload than the
// arena's initial capacity to verify two properties of the overflow
// handling: add never calls sink (critical for the fast reader, where
// add runs inside ReadBatch's callback before consPos is committed), and
// the arena grows via append without corrupting payloads already queued
// — their bytes must survive the reallocation intact.
func TestBatchBuilderArenaOverflow(t *testing.T) {
	var got [][]byte
	sinkCalls := 0
	sink := func(_ int, pkts []Packet) error {
		sinkCalls++
		for _, p := range pkts {
			cp := make([]byte, len(p.Data))
			copy(cp, p.Data)
			got = append(got, cp)
		}
		return nil
	}

	bb := newBatchBuilder(0, sink)
	// Shrink the arena so the packets below overflow it well before the
	// explicit flush, forcing append to reallocate mid-batch.
	bb.arena = make([]byte, 0, 32)

	caplens := []int{16, 16, 16, 16, 48}
	src := make([]byte, MetadataSize+64)
	for i, caplen := range caplens {
		raw := makeRecord(src, byte(i+1), caplen)
		pkt, err := ParseRawSample(raw)
		if err != nil {
			t.Fatalf("ParseRawSample: %v", err)
		}
		bb.add(pkt)
		// Overwrite the shared source to prove the payload was copied.
		for k := range src {
			src[k] = 0
		}
	}

	// add() must not have flushed despite overflowing the arena.
	if sinkCalls != 0 {
		t.Fatalf("sink called %d times during add (want 0; add must not flush)", sinkCalls)
	}
	// The total payload exceeded the initial 32 B, so the arena must
	// have grown.
	if cap(bb.arena) <= 32 {
		t.Fatalf("arena cap = %d, want > 32 (append should have grown it)", cap(bb.arena))
	}

	bb.flush()

	if sinkCalls != 1 {
		t.Fatalf("sink called %d times, want 1 (single explicit flush)", sinkCalls)
	}
	if len(got) != len(caplens) {
		t.Fatalf("got %d packets, want %d", len(got), len(caplens))
	}
	for i, caplen := range caplens {
		if len(got[i]) != caplen {
			t.Fatalf("packet %d len = %d, want %d", i, len(got[i]), caplen)
		}
		for j, b := range got[i] {
			if b != byte(i+1) {
				t.Fatalf("packet %d byte %d = %#x, want %#x (survived realloc)", i, j, b, byte(i+1))
			}
		}
	}
}
