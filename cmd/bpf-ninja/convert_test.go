package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/output"
)

// TestConvertRejectsV1 pins the raw-dump format guard: a V1 file (20-byte
// record metadata, bpf-ninja 0.25 and earlier) is refused with a message
// that names the format and the release that reads it.
func TestConvertRejectsV1(t *testing.T) {
	hdr := make([]byte, output.RawDumpHeaderSize)
	copy(hdr, "XNINJA-RAW-V1\x00\x00\x00")
	path := filepath.Join(t.TempDir(), "old.cpu0.raw")
	if err := os.WriteFile(path, hdr, 0o644); err != nil {
		t.Fatal(err)
	}
	fw, err := output.NewFastNgWriter(&bytes.Buffer{}, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	_, err = convertFile(path, fw)
	if err == nil || !strings.Contains(err.Error(), "format V1") || !strings.Contains(err.Error(), "0.25") {
		t.Fatalf("convertFile(V1) error = %v, want a 'format V1' rejection naming 0.25", err)
	}
}

// TestConvertOriginalLength converts a 4-byte cut of a 1500-byte packet
// from a V3 dump (the EPB keeps both lengths) and a V2 dump, whose 28-byte
// metadata has no orig_len (the EPB reads as uncut).
func TestConvertOriginalLength(t *testing.T) {
	for _, c := range []struct {
		name    string
		v2      bool
		origLen int
	}{{"v3", false, 1500}, {"v2", true, 4}} {
		path := filepath.Join(t.TempDir(), "s.W0.cpu0.raw")
		w, err := output.NewRawDumpWriter(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		record := make([]byte, capture.MetadataSize+4)
		binary.NativeEndian.PutUint16(record[capture.OffsetCapLen:], 4)
		binary.NativeEndian.PutUint32(record[capture.OffsetOrigLen:], 1500)
		if err := w.WriteRaw(record); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if c.v2 {
			// Rewrite as V2: the old magic, and the record without orig_len.
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			copy(raw, "XNINJA-RAW-V2\x00\x00\x00")
			meta := output.RawDumpHeaderSize + capture.OffsetOrigLen
			if err := os.WriteFile(path, slices.Concat(raw[:meta], raw[meta+4:]), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		var buf bytes.Buffer
		fw, err := output.NewFastNgWriter(&buf, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := convertFile(path, fw); err != nil || n != 1 {
			t.Fatalf("%s: convertFile = %d, %v", c.name, n, err)
		}
		r, err := pcapgo.NewNgReader(&buf, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			t.Fatal(err)
		}
		if _, ci, err := r.ReadPacketData(); err != nil || ci.CaptureLength != 4 || ci.Length != c.origLen {
			t.Fatalf("%s: EPB captured %d original %d (%v), want 4 and %d", c.name, ci.CaptureLength, ci.Length, err, c.origLen)
		}
	}
}
