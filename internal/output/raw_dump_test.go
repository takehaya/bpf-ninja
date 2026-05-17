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

func TestRawDumpWriter_HeaderAndRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.W1234567890.cpu0.raw")

	w, err := NewRawDumpWriter(path, 1234567890)
	if err != nil {
		t.Fatalf("NewRawDumpWriter: %v", err)
	}

	// Synthesise a ringbuf record: 16B metadata + 4B data.
	record := make([]byte, capture.MetadataSize+4)
	binary.NativeEndian.PutUint64(record[0:8], 999_000) // kernel_ts
	binary.NativeEndian.PutUint32(record[8:12], 2)      // action = XDP_PASS
	record[12] = 2                                       // mode = xdp-native
	binary.NativeEndian.PutUint16(record[14:16], 4)     // caplen
	copy(record[capture.MetadataSize:], []byte{0xde, 0xad, 0xbe, 0xef})

	if err := w.WriteRaw(record); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back and verify header.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	hdr := make([]byte, RawDumpHeaderSize)
	if _, err := io.ReadFull(f, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if !bytes.Equal(hdr[0:16], RawDumpMagic) {
		t.Errorf("magic mismatch: got %q, want %q", hdr[0:16], RawDumpMagic)
	}
	if binary.BigEndian.Uint32(hdr[16:20]) != RawDumpEndianMagic {
		t.Errorf("endian magic mismatch: got %#x", binary.BigEndian.Uint32(hdr[16:20]))
	}
	if got := binary.LittleEndian.Uint64(hdr[20:28]); got != 1234567890 {
		t.Errorf("wall_offset_ns: got %d, want 1234567890", got)
	}

	// Read the record bytes and verify they match exactly.
	got := make([]byte, len(record))
	if _, err := io.ReadFull(f, got); err != nil {
		t.Fatalf("read record: %v", err)
	}
	if !bytes.Equal(got, record) {
		t.Errorf("record mismatch:\n  got %x\n want %x", got, record)
	}
	// File should be exactly header + record bytes.
	extra := make([]byte, 1)
	if n, err := f.Read(extra); err != io.EOF || n != 0 {
		t.Errorf("expected EOF after record, got n=%d err=%v", n, err)
	}
}

