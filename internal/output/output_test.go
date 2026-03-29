package output

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/xdp-ninja/internal/capture"
)

// dummy Ethernet frame (14-byte header + 4 bytes payload)
var testPktData = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
	0x08, 0x00, // ethertype IPv4
	0xde, 0xad, 0xbe, 0xef, // payload
}

func newTestWriter(buf *bytes.Buffer, mode string) *Writer {
	w := &Writer{}
	var err error
	if mode == "exit" {
		err = w.initExitMode(buf)
	} else {
		w.pcapWriter, err = pcapgo.NewNgWriter(buf, layers.LinkTypeEthernet)
	}
	if err != nil {
		panic(err)
	}
	return w
}

func TestExitModeInterfaces(t *testing.T) {
	var buf bytes.Buffer
	w := newTestWriter(&buf, "exit")

	// Write one packet per action (0-4)
	for action := uint32(0); action <= 4; action++ {
		pkt := capture.Packet{
			Timestamp: time.Unix(1000000, 0),
			Data:      testPktData,
			Action:    action,
			Mode:      1,
		}
		if err := w.Write(pkt); err != nil {
			t.Fatalf("Write action=%d: %v", action, err)
		}
	}

	// Read back
	r, err := pcapgo.NewNgReader(&buf, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader: %v", err)
	}

	// Read all packets first (reader parses IDBs lazily)
	for action := uint32(0); action <= 4; action++ {
		_, ci, err := r.ReadPacketData()
		if err != nil {
			t.Fatalf("ReadPacketData action=%d: %v", action, err)
		}
		if ci.InterfaceIndex != int(action) {
			t.Errorf("action=%d: InterfaceIndex = %d, want %d", action, ci.InterfaceIndex, action)
		}
	}

	// Now verify interface names
	expectedNames := []string{"xdp:ABORTED", "xdp:DROP", "xdp:PASS", "xdp:TX", "xdp:REDIRECT"}
	if r.NInterfaces() != len(expectedNames) {
		t.Fatalf("NInterfaces = %d, want %d", r.NInterfaces(), len(expectedNames))
	}
	for i, name := range expectedNames {
		iface, err := r.Interface(i)
		if err != nil {
			t.Fatalf("Interface(%d): %v", i, err)
		}
		if iface.Name != name {
			t.Errorf("Interface(%d).Name = %q, want %q", i, iface.Name, name)
		}
	}
}

func TestExitModeUnknownAction(t *testing.T) {
	var buf bytes.Buffer
	w := newTestWriter(&buf, "exit")

	pkt := capture.Packet{
		Timestamp: time.Unix(1000000, 0),
		Data:      testPktData,
		Action:    99, // unknown
		Mode:      1,
	}
	if err := w.Write(pkt); err != nil {
		t.Fatalf("Write: %v", err)
	}

	r, err := pcapgo.NewNgReader(&buf, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader: %v", err)
	}

	_, ci, err := r.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData: %v", err)
	}
	if ci.InterfaceIndex != 0 {
		t.Errorf("InterfaceIndex = %d, want 0 (fallback)", ci.InterfaceIndex)
	}
}

func TestEntryModeUnchanged(t *testing.T) {
	var buf bytes.Buffer
	w := newTestWriter(&buf, "entry")

	if w.actionToID != nil {
		t.Fatal("actionToID should be nil in entry mode")
	}

	pkt := capture.Packet{
		Timestamp: time.Unix(1000000, 0),
		Data:      testPktData,
		Action:    0,
		Mode:      0,
	}
	if err := w.Write(pkt); err != nil {
		t.Fatalf("Write: %v", err)
	}

	r, err := pcapgo.NewNgReader(&buf, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader: %v", err)
	}

	if r.NInterfaces() != 1 {
		t.Fatalf("NInterfaces = %d, want 1", r.NInterfaces())
	}

	_, ci, err := r.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData: %v", err)
	}
	if ci.InterfaceIndex != 0 {
		t.Errorf("InterfaceIndex = %d, want 0", ci.InterfaceIndex)
	}
}
