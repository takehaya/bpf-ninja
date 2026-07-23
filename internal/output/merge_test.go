package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/bpf-ninja/internal/capture"
)

// xdpExitConfig is the exit-mode layout the XDP hook produces
// (mirrors internal/hook without importing it — output stays below hook
// in the layering, tests included).
func xdpExitConfig() Config {
	return Config{
		IsFexit:  true,
		HookName: "xdp",
		Actions: []ActionName{
			{Value: 0, Name: "xdp:ABORTED"},
			{Value: 1, Name: "xdp:DROP"},
			{Value: 2, Name: "xdp:PASS"},
			{Value: 3, Name: "xdp:TX"},
			{Value: 4, Name: "xdp:REDIRECT"},
		},
	}
}

// writeShardFile writes a single-shard pcap-ng with packets at the given
// second offsets from base, each a minimal 20-byte frame.
func writeShardFile(t *testing.T, path string, base time.Time, secs []int) {
	t.Helper()
	w, err := NewWriter(path, Config{})
	if err != nil {
		t.Fatalf("NewWriter(%s): %v", path, err)
	}
	for _, s := range secs {
		frame := make([]byte, 20)
		frame[0] = byte(s) // tag the frame so we can check ordering
		if err := w.Write(capture.Packet{Timestamp: base.Add(time.Duration(s) * time.Second), Data: frame}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close(%s): %v", path, err)
	}
}

// TestMergeShardFiles verifies that per-CPU shards are merged into a single
// globally time-ordered pcap-ng, and that missing shard indices are
// skipped without error.
func TestMergeShardFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "out.pcap")
	epoch := time.Unix(1700000000, 0).UTC()

	// Interleaved across shards; shard 1 has no file (gap tolerated).
	writeShardFile(t, base+".cpu0", epoch, []int{1, 3, 5})
	writeShardFile(t, base+".cpu2", epoch, []int{2, 4})

	// numShards=3 so .cpu1 (nonexistent) exercises the skip path.
	if err := MergeShardFiles(base, 3, Config{}); err != nil {
		t.Fatalf("MergeShardFiles: %v", err)
	}

	f, err := os.Open(base)
	if err != nil {
		t.Fatalf("open merged: %v", err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NgReader: %v", err)
	}

	var order []int
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		order = append(order, int(data[0]))
	}

	want := []int{1, 2, 3, 4, 5}
	if len(order) != len(want) {
		t.Fatalf("merged packet count = %d, want %d (order=%v)", len(order), len(want), order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("merged order = %v, want %v", order, want)
		}
	}
}

// TestMergeShardFilesFexitPreservesAction verifies that in fexit mode the
// merged base keeps each packet's per-action interface (xdp:PASS/DROP/...),
// i.e. the source interface index survives the merge rather than collapsing
// to interface 0.
func TestMergeShardFilesFexitPreservesAction(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "exit.pcap")
	epoch := time.Unix(1700000000, 0).UTC()

	// shard 0: two packets with actions 2 (PASS) and 1 (DROP).
	w0, err := NewWriter(base+".cpu0", xdpExitConfig())
	if err != nil {
		t.Fatalf("NewWriter fexit: %v", err)
	}
	if err := w0.Write(capture.Packet{Timestamp: epoch.Add(1 * time.Second), Data: make([]byte, 20), Action: 2}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w0.Write(capture.Packet{Timestamp: epoch.Add(3 * time.Second), Data: make([]byte, 20), Action: 1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w0.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := MergeShardFiles(base, 1, xdpExitConfig()); err != nil {
		t.Fatalf("MergeShardFiles fexit: %v", err)
	}

	f, err := os.Open(base)
	if err != nil {
		t.Fatalf("open merged: %v", err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NgReader: %v", err)
	}

	var ifaces []int
	for {
		_, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		ifaces = append(ifaces, ci.InterfaceIndex)
	}
	// interface index == action (identity map in initExitMode): 2 then 1.
	want := []int{2, 1}
	if len(ifaces) != len(want) || ifaces[0] != want[0] || ifaces[1] != want[1] {
		t.Fatalf("merged interface indices = %v, want %v (action interface lost)", ifaces, want)
	}
}

// TestMergeShardFilesEmpty verifies merging when no shard files exist
// produces a valid (empty) pcap-ng rather than erroring.
func TestMergeShardFilesEmpty(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "none.pcap")
	if err := MergeShardFiles(base, 4, Config{}); err != nil {
		t.Fatalf("MergeShardFiles with no shards: %v", err)
	}
	f, err := os.Open(base)
	if err != nil {
		t.Fatalf("open merged: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions); err != nil {
		t.Fatalf("merged empty file is not valid pcap-ng: %v", err)
	}
}
