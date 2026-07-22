package output

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// writePacketsToFile writes pkts through a fresh Writer at path. fast selects
// the FastNgWriter (BPF_NINJA_FAST_PCAPNG=1, the default) vs the gopacket
// NgWriter (BPF_NINJA_FAST_PCAPNG=0); both are set explicitly so the test
// does not depend on the ambient default.
func writePacketsToFile(t *testing.T, path string, pkts []capture.Packet, fast bool) {
	t.Helper()
	if fast {
		t.Setenv("BPF_NINJA_FAST_PCAPNG", "1")
	} else {
		t.Setenv("BPF_NINJA_FAST_PCAPNG", "0")
	}
	w, err := NewWriter(path, false)
	if err != nil {
		t.Fatalf("NewWriter(fast=%v): %v", fast, err)
	}
	if err := w.WriteBatch(pkts); err != nil {
		t.Fatalf("WriteBatch(fast=%v): %v", fast, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close(fast=%v): %v", fast, err)
	}
}

func testPackets() []capture.Packet {
	// A mix of lengths and sub-microsecond timestamps so any timestamp
	// truncation or length-padding difference between the two writers shows up.
	base := time.Unix(1700000000, 123456789)
	mk := func(i, n int) capture.Packet {
		data := make([]byte, n)
		for j := range data {
			data[j] = byte((i*7 + j) & 0xff)
		}
		return capture.Packet{Timestamp: base.Add(time.Duration(i) * 137 * time.Nanosecond), Data: data, CapLen: uint16(n)}
	}
	return []capture.Packet{mk(0, 64), mk(1, 65), mk(2, 128), mk(3, 1), mk(4, 1500), mk(5, 60)}
}

// readbackPackets reads every packet from a pcap-ng file. Only a clean EOF
// ends the read — any other error is a decode failure and fails the test,
// so a corrupt file cannot pass as a short-but-equal packet list.
func readbackPackets(t *testing.T, path string) []capture.Packet {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader(%s): %v", path, err)
	}
	var out []capture.Packet
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("ReadPacketData(%s) after %d packets: %v", path, len(out), err)
		}
		cp := make([]byte, len(data))
		copy(cp, data)
		out = append(out, capture.Packet{Timestamp: ci.Timestamp, Data: cp})
	}
}

// TestFastNgWriterEquivalent is the equivalence gate for defaulting the
// FastNgWriter: its file must read back to exactly the packets gopacket's
// NgWriter produces (same count, timestamps, and bytes). The two are not
// byte-identical on disk — gopacket emits optional SHB/IDB description
// strings this writer omits — so equivalence is checked at the packet level,
// which is what any consumer sees.
func TestFastNgWriterEquivalent(t *testing.T) {
	pkts := testPackets()
	dir := t.TempDir()
	fastPath := filepath.Join(dir, "fast.pcapng")
	stdPath := filepath.Join(dir, "std.pcapng")

	writePacketsToFile(t, fastPath, pkts, true)
	writePacketsToFile(t, stdPath, pkts, false)

	fast := readbackPackets(t, fastPath)
	std := readbackPackets(t, stdPath)
	if len(fast) != len(std) || len(fast) != len(pkts) {
		t.Fatalf("packet count mismatch: fast=%d std=%d want=%d", len(fast), len(std), len(pkts))
	}
	for i := range fast {
		if !fast[i].Timestamp.Equal(std[i].Timestamp) {
			t.Fatalf("packet %d: ts fast=%v std=%v", i, fast[i].Timestamp, std[i].Timestamp)
		}
		if !bytes.Equal(fast[i].Data, std[i].Data) {
			t.Fatalf("packet %d: data mismatch (fast %d vs std %d bytes)", i, len(fast[i].Data), len(std[i].Data))
		}
	}
}

// TestFastNgWriterReadback confirms the fast-path file is a valid pcap-ng that
// reads back to the same packets (data + timestamp), independent of the
// byte-identity check above.
func TestFastNgWriterReadback(t *testing.T) {
	pkts := testPackets()
	path := filepath.Join(t.TempDir(), "fast.pcapng")
	writePacketsToFile(t, path, pkts, true)

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader: %v", err)
	}
	for i, want := range pkts {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			t.Fatalf("packet %d: read: %v", i, err)
		}
		if !bytes.Equal(data, want.Data) {
			t.Fatalf("packet %d: data mismatch (%d vs %d bytes)", i, len(data), len(want.Data))
		}
		if !ci.Timestamp.Equal(want.Timestamp) {
			t.Fatalf("packet %d: ts mismatch: got %v want %v", i, ci.Timestamp, want.Timestamp)
		}
	}
	if _, _, err := r.ReadPacketData(); err == nil {
		t.Fatalf("expected EOF after %d packets", len(pkts))
	}
}
