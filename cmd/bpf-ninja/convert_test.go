package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"

	"github.com/takehaya/bpf-ninja/internal/output"
)

// TestConvertRejectsV1 pins the raw-dump format guard: a V1 file (20-byte
// record metadata, before the packet id) is refused with a message that
// names the format, not a generic magic mismatch.
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
	if err == nil || !strings.Contains(err.Error(), "format V1") {
		t.Fatalf("convertFile(V1) error = %v, want a 'format V1' rejection", err)
	}
}
