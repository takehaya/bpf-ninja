package capture

import (
	"encoding/binary"
	"testing"
)

func TestParsePacket(t *testing.T) {
	// metadata (16B): kernel_ts=12345, action=2 (PASS), mode=1 (exit), pad=0, caplen=4
	pktData := []byte{0xde, 0xad, 0xbe, 0xef}

	raw := make([]byte, MetadataSize+len(pktData))
	binary.NativeEndian.PutUint64(raw[0:8], 12345)                     // kernel_ts_ns
	binary.NativeEndian.PutUint32(raw[8:12], 2)                        // action = XDP_PASS
	raw[12] = 1                                                         // mode = exit
	raw[13] = 0                                                         // pad
	binary.NativeEndian.PutUint16(raw[14:16], uint16(len(pktData)))    // caplen
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
	raw[12] = 0                                  // mode = entry

	pkt, err := ParseRawSample(raw)
	if err != nil {
		t.Fatalf("ParseRawSample failed: %v", err)
	}
	if len(pkt.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(pkt.Data))
	}
}
