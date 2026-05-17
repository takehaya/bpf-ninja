package fastrb

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"unsafe"
)

// newTestReader builds a Reader backed by Go-allocated slices instead
// of mmap, so the walk logic can be exercised without a real BPF map.
// The "ring" slice is sized 2 × ringSize to mirror the kernel's
// double-mapping; tests must write to BOTH halves when a record
// straddles the boundary.
func newTestReader(ringSize int) *Reader {
	cons := make([]byte, 8)
	prod := make([]byte, 8+2*ringSize)
	return &Reader{
		consMmap: cons,
		prodMmap: prod,
		consPos:  (*uintptr)(unsafe.Pointer(&cons[0])),
		prodPos:  (*uintptr)(unsafe.Pointer(&prod[0])),
		ring:     prod[8:],
		mask:     uintptr(ringSize - 1),
		ringSize: ringSize,
		epollFD:  -1,
	}
}

// writeRecord stores a record into the ring at the given offset.
// dataLen is the payload byte count; flags can OR in BUSY/DISCARD.
// Returns the number of bytes consumed (header + aligned data).
func writeRecord(ring []byte, off uintptr, dataLen uint32, flags uint32, fill byte) uintptr {
	mask := uintptr(len(ring)/2 - 1)
	hdrOff := off & mask
	binary.LittleEndian.PutUint32(ring[hdrOff:], dataLen|flags)
	// Zero the pg_off pad.
	binary.LittleEndian.PutUint32(ring[hdrOff+4:], 0)
	dataOff := (off + uintptr(hdrSize)) & mask
	for i := uint32(0); i < dataLen; i++ {
		ring[dataOff+uintptr(i)] = fill
	}
	aligned := (uintptr(dataLen) + 7) &^ 7
	return uintptr(hdrSize) + aligned
}

func setProd(r *Reader, v uintptr) {
	atomic.StoreUintptr(r.prodPos, v)
}

func TestReadBatch_ThreeRecords(t *testing.T) {
	r := newTestReader(4096)
	advance := uintptr(0)
	advance += writeRecord(r.ring, advance, 16, 0, 0xaa)
	advance += writeRecord(r.ring, advance, 32, 0, 0xbb)
	advance += writeRecord(r.ring, advance, 8, 0, 0xcc)
	setProd(r, advance)

	var got [][]byte
	n := r.ReadBatch(func(rec []byte) {
		// Copy out — reader returns aliased ring memory.
		c := make([]byte, len(rec))
		copy(c, rec)
		got = append(got, c)
	})
	if n != 3 {
		t.Fatalf("n=%d, want 3", n)
	}
	if len(got[0]) != 16 || got[0][0] != 0xaa {
		t.Errorf("rec 0: len=%d head=%x, want 16 / 0xaa", len(got[0]), got[0][0])
	}
	if len(got[1]) != 32 || got[1][0] != 0xbb {
		t.Errorf("rec 1: len=%d head=%x, want 32 / 0xbb", len(got[1]), got[1][0])
	}
	if len(got[2]) != 8 || got[2][0] != 0xcc {
		t.Errorf("rec 2: len=%d head=%x, want 8 / 0xcc", len(got[2]), got[2][0])
	}
	if got := *r.consPos; got != advance {
		t.Errorf("consPos after batch: got %d, want %d", got, advance)
	}
}

func TestReadBatch_BusyStopsWalk(t *testing.T) {
	r := newTestReader(4096)
	off := uintptr(0)
	off += writeRecord(r.ring, off, 16, 0, 0x11)         // committed
	off += writeRecord(r.ring, off, 16, hdrBusyBit, 0x22) // busy — stop here
	off += writeRecord(r.ring, off, 16, 0, 0x33)         // committed but unreachable
	setProd(r, off)

	n := r.ReadBatch(func(rec []byte) {
		if rec[0] != 0x11 {
			t.Errorf("delivered busy/unreachable record: head=%x", rec[0])
		}
	})
	if n != 1 {
		t.Fatalf("n=%d, want 1 (busy should stop walk)", n)
	}
	// consPos advances past the committed record only.
	if got := *r.consPos; got != uintptr(hdrSize)+16 {
		t.Errorf("consPos: got %d, want %d", got, uintptr(hdrSize)+16)
	}
}

func TestReadBatch_DiscardSkipped(t *testing.T) {
	r := newTestReader(4096)
	off := uintptr(0)
	off += writeRecord(r.ring, off, 16, 0, 0xaa)
	off += writeRecord(r.ring, off, 16, hdrDiscardBit, 0xbb)
	off += writeRecord(r.ring, off, 16, 0, 0xcc)
	setProd(r, off)

	var heads []byte
	n := r.ReadBatch(func(rec []byte) {
		heads = append(heads, rec[0])
	})
	if n != 2 {
		t.Fatalf("n=%d, want 2 (discard counted but not delivered)", n)
	}
	if heads[0] != 0xaa || heads[1] != 0xcc {
		t.Errorf("delivered heads = %x, want [aa cc]", heads)
	}
	if got := *r.consPos; got != off {
		t.Errorf("consPos: got %d, want %d (cover all three records)", got, off)
	}
}

func TestReadBatch_Wraparound(t *testing.T) {
	// 64-byte ring with cons starting near the end. The header sits
	// at offset 56..59 of the low mirror (cons & mask = 56), payload
	// of 24 bytes starts at linear offset 64 → masked to offset 0 of
	// the low mirror. The reader walks header from low-mirror offset
	// 56, then payload from low-mirror offset 0..23 — exercising the
	// "& mask" wrap path.
	ringSize := 64
	r := newTestReader(ringSize)

	startOff := uintptr(ringSize - 8) // header at low-mirror offset 56..63
	// Header: dataLen = 24, no flags.
	binary.LittleEndian.PutUint32(r.ring[startOff:], 24)
	binary.LittleEndian.PutUint32(r.ring[startOff+4:], 0) // pg_off pad
	// Payload spans linear offsets 64..87 → masked to low-mirror 0..23.
	for i := uintptr(0); i < 24; i++ {
		r.ring[i] = byte(0x40 + i)
	}
	*r.consPos = startOff
	setProd(r, startOff+uintptr(hdrSize)+24)

	var rec []byte
	n := r.ReadBatch(func(b []byte) {
		c := make([]byte, len(b))
		copy(c, b)
		rec = c
	})
	if n != 1 {
		t.Fatalf("n=%d, want 1", n)
	}
	if len(rec) != 24 {
		t.Fatalf("payload len=%d, want 24", len(rec))
	}
	for i := 0; i < 24; i++ {
		if rec[i] != byte(0x40+i) {
			t.Errorf("payload[%d]=%x, want %x", i, rec[i], 0x40+i)
		}
	}
}

func TestReadBatch_EmptyRing(t *testing.T) {
	r := newTestReader(4096)
	setProd(r, 0)
	n := r.ReadBatch(func([]byte) {
		t.Error("callback called on empty ring")
	})
	if n != 0 {
		t.Errorf("n=%d, want 0", n)
	}
}

func TestReadBatch_AllDiscard(t *testing.T) {
	r := newTestReader(4096)
	off := uintptr(0)
	off += writeRecord(r.ring, off, 16, hdrDiscardBit, 0xaa)
	off += writeRecord(r.ring, off, 16, hdrDiscardBit, 0xbb)
	off += writeRecord(r.ring, off, 16, hdrDiscardBit, 0xcc)
	setProd(r, off)
	n := r.ReadBatch(func([]byte) {
		t.Error("callback called for discarded record")
	})
	if n != 0 {
		t.Fatalf("n=%d, want 0 (all discards)", n)
	}
	if got := *r.consPos; got != off {
		t.Errorf("consPos: got %d, want %d (must cover all discards)", got, off)
	}
}

func TestReadBatch_ZeroLengthPayload(t *testing.T) {
	r := newTestReader(4096)
	off := uintptr(0)
	off += writeRecord(r.ring, off, 0, 0, 0)
	setProd(r, off)
	calls := 0
	n := r.ReadBatch(func(rec []byte) {
		calls++
		if len(rec) != 0 {
			t.Errorf("len(rec)=%d, want 0", len(rec))
		}
	})
	if n != 1 || calls != 1 {
		t.Errorf("n=%d calls=%d, want 1/1", n, calls)
	}
}

func TestReadBatch_BusyClearsThenDelivers(t *testing.T) {
	// Models "kernel mid-write": first call sees BUSY at pos 0 and
	// returns n=0 without advancing consPos. Producer commits the
	// record; second call delivers it.
	r := newTestReader(4096)
	writeRecord(r.ring, 0, 16, hdrBusyBit, 0xee)
	setProd(r, uintptr(hdrSize)+16)
	if n := r.ReadBatch(func([]byte) {
		t.Error("callback called on busy record")
	}); n != 0 {
		t.Fatalf("first n=%d, want 0", n)
	}
	if *r.consPos != 0 {
		t.Errorf("consPos advanced past busy record: got %d, want 0", *r.consPos)
	}
	// Producer clears the busy bit.
	writeRecord(r.ring, 0, 16, 0, 0xee)
	if n := r.ReadBatch(func(rec []byte) {
		if rec[0] != 0xee {
			t.Errorf("rec head=%x, want 0xee", rec[0])
		}
	}); n != 1 {
		t.Fatalf("second n=%d, want 1", n)
	}
}
