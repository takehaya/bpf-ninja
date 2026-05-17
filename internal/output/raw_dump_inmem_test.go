package output

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

func makeRecord(t *testing.T, caplen uint16, fill byte) []byte {
	t.Helper()
	rec := make([]byte, capture.MetadataSize+int(caplen))
	binary.NativeEndian.PutUint64(rec[0:8], 999_000)
	binary.NativeEndian.PutUint32(rec[8:12], 2)
	rec[12] = 2
	binary.NativeEndian.PutUint16(rec[14:16], caplen)
	for i := 0; i < int(caplen); i++ {
		rec[capture.MetadataSize+i] = fill
	}
	return rec
}

func TestInMemoryRawDumpWriter_HeaderAndRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inmem.W1234567890.cpu0.raw")

	w, err := NewInMemoryRawDumpWriter(path, 1234567890, 64*1024)
	if err != nil {
		t.Fatalf("NewInMemoryRawDumpWriter: %v", err)
	}
	rec := makeRecord(t, 4, 0xab)
	copy(rec[capture.MetadataSize:], []byte{0xde, 0xad, 0xbe, 0xef})
	if err := w.WriteRaw(rec); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(RawDumpHeaderSize + len(rec)); st.Size() != want {
		t.Errorf("file size: got %d, want %d", st.Size(), want)
	}

	f, _ := os.Open(path)
	defer func() { _ = f.Close() }()
	hdr := make([]byte, RawDumpHeaderSize)
	if _, err := io.ReadFull(f, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !bytes.Equal(hdr[0:16], RawDumpMagic) {
		t.Errorf("magic mismatch")
	}
	if got := binary.LittleEndian.Uint64(hdr[20:28]); got != 1234567890 {
		t.Errorf("wall_offset_ns: got %d", got)
	}
	got := make([]byte, len(rec))
	if _, err := io.ReadFull(f, got); err != nil {
		t.Fatalf("read record: %v", err)
	}
	if !bytes.Equal(got, rec) {
		t.Errorf("record mismatch")
	}
}

func TestInMemoryRawDumpWriter_TrimsKernelSlack(t *testing.T) {
	dir := t.TempDir()
	w, err := NewInMemoryRawDumpWriter(filepath.Join(dir, "trim.W0.cpu0.raw"), 0, 64*1024)
	if err != nil {
		t.Fatal(err)
	}
	// Kernel slot 16 + 128 B, real caplen 8 → writer should persist
	// only 16 + 8 = 24 B per record.
	const realCap = 8
	rec := make([]byte, capture.MetadataSize+128)
	binary.NativeEndian.PutUint16(rec[14:16], realCap)
	for i := 0; i < realCap; i++ {
		rec[capture.MetadataSize+i] = byte(0xa0 + i)
	}
	if err := w.WriteRaw(rec); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, "trim.W0.cpu0.raw"))
	if want := int64(RawDumpHeaderSize + capture.MetadataSize + realCap); st.Size() != want {
		t.Errorf("file size: got %d, want %d (must trim trailing slack)", st.Size(), want)
	}
}

func TestInMemoryRawDumpWriter_OverflowFlushAndResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overflow.W0.cpu0.raw")
	// Buffer just big enough for header + 2 small records.
	// 32 (header) + 2 × (16 + 4) = 72; size buffer = 80.
	w, err := NewInMemoryRawDumpWriter(path, 0, 80)
	if err != nil {
		t.Fatal(err)
	}
	const recCap = 4
	recA := makeRecord(t, recCap, 0xaa)
	recB := makeRecord(t, recCap, 0xbb)
	recC := makeRecord(t, recCap, 0xcc) // forces overflow

	for _, r := range [][]byte{recA, recB, recC} {
		if err := w.WriteRaw(r); err != nil {
			t.Fatalf("WriteRaw: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	// File must contain: header + recA + recB + recC, exactly.
	wantLen := RawDumpHeaderSize + 3*(capture.MetadataSize+recCap)
	if len(data) != wantLen {
		t.Fatalf("file len: got %d, want %d", len(data), wantLen)
	}
	for i, want := range []byte{0xaa, 0xbb, 0xcc} {
		off := RawDumpHeaderSize + i*(capture.MetadataSize+recCap) + capture.MetadataSize
		if data[off] != want {
			t.Errorf("record %d head byte: got %x, want %x", i, data[off], want)
		}
	}
}

func TestInMemoryRawDumpWriter_RejectsTooShort(t *testing.T) {
	dir := t.TempDir()
	w, err := NewInMemoryRawDumpWriter(filepath.Join(dir, "short.W0.cpu0.raw"), 0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := w.WriteRaw(make([]byte, capture.MetadataSize-1)); err == nil {
		t.Error("expected error for under-MetadataSize record")
	}
}
