package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/output"
)

// testutilPackets returns two tiny timestamp-ordered packets.
func testutilPackets() []capture.Packet {
	base := time.Unix(1700000000, 0)
	return []capture.Packet{
		{Timestamp: base, Data: []byte{1, 2, 3, 4}},
		{Timestamp: base.Add(time.Millisecond), Data: []byte{5, 6, 7, 8}},
	}
}

func countPcapPackets(path string) (int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = fh.Close() }()
	r, err := pcapgo.NewNgReader(fh, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		if _, _, err := r.ReadPacketData(); err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		n++
	}
}

func newTestFinalizer(t *testing.T, shards int) *tagFinalizer {
	t.Helper()
	base := filepath.Join(t.TempDir(), "out.pcap")
	return newTagFinalizer(base, output.Config{}, shards)
}

// A tag must survive one full quiet cycle after leaving the union
// before it finalizes: cycle 1 makes it a candidate, cycle 2 confirms.
func TestStepTwoCycleQuiesce(t *testing.T) {
	f := newTestFinalizer(t, 2)
	st := f.stateFor(7)

	if done := f.step([]uint32{7}); len(done) != 0 {
		t.Fatalf("finalized while still in the union: %v", done)
	}
	if done := f.step(nil); len(done) != 0 {
		t.Fatalf("finalized on the first quiet cycle: %v", done)
	}
	if done := f.step(nil); len(done) != 1 || done[0] != 7 {
		t.Fatalf("second quiet cycle = %v, want [7]", done)
	}
	if !st.finalized.Load() {
		t.Fatal("finalized flag not set")
	}
	if done := f.step(nil); len(done) != 0 {
		t.Fatalf("finalized twice: %v", done)
	}
}

// Records arriving between the two cycles (draining ringbuf backlog)
// must reset the candidate.
func TestStepActivityResetsCandidate(t *testing.T) {
	f := newTestFinalizer(t, 1)
	st := f.stateFor(3)

	f.step(nil)       // candidate at activity 0
	st.activity.Add(1) // backlog drained a batch
	if done := f.step(nil); len(done) != 0 {
		t.Fatalf("finalized despite activity during the cycle: %v", done)
	}
	if done := f.step(nil); len(done) != 1 || done[0] != 3 {
		t.Fatalf("quiet re-cycle = %v, want [3]", done)
	}
}

// A tag re-added to the union while pending must drop out of the
// candidate set and start over after the next removal.
func TestStepReappearanceResetsCandidate(t *testing.T) {
	f := newTestFinalizer(t, 1)
	f.stateFor(5)

	f.step(nil) // candidate
	if done := f.step([]uint32{5}); len(done) != 0 {
		t.Fatalf("finalized while back in the union: %v", done)
	}
	f.step(nil) // candidate again
	if done := f.step(nil); len(done) != 1 || done[0] != 5 {
		t.Fatalf("post-re-removal cycles = %v, want [5]", done)
	}
}

// Union-seen tags (registered via step, no traffic) finalize too, so a
// zero-traffic tag still produces its ack file. Tag 0 never does.
func TestStepUnionSeenAndTagZero(t *testing.T) {
	f := newTestFinalizer(t, 1)

	f.step([]uint32{9}) // tag 9 exists only in the set map
	f.step(nil)
	if done := f.step(nil); len(done) != 1 || done[0] != 9 {
		t.Fatalf("union-seen tag = %v, want [9]", done)
	}

	f.stateFor(0) // traffic with no set match
	f.step(nil)
	if done := f.step(nil); len(done) != 0 {
		t.Fatalf("tag 0 finalized: %v", done)
	}
}

// finalize with no open writers (zero-traffic tag) must still produce a
// valid merged file — the completion ack.
func TestFinalizeZeroTrafficProducesFile(t *testing.T) {
	f := newTestFinalizer(t, 4)
	if err := f.finalize(9); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	merged := output.TagMergedPath(f.basePath, 9)
	info, err := os.Stat(merged)
	if err != nil {
		t.Fatalf("merged file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("merged file is empty (want a valid pcap-ng header)")
	}
}

// finalize must close registered writers (flushing their buffers) and
// merge the shard contents into the per-tag file.
func TestFinalizeClosesWritersAndMerges(t *testing.T) {
	f := newTestFinalizer(t, 2)
	pkts := testutilPackets()

	for shard := range 2 {
		w, err := output.NewWriter(output.TagShardPath(f.basePath, shard, 1), output.Config{})
		if err != nil {
			t.Fatalf("NewWriter shard %d: %v", shard, err)
		}
		if err := w.WriteBatch(pkts[shard : shard+1]); err != nil {
			t.Fatalf("WriteBatch shard %d: %v", shard, err)
		}
		f.register(1, shard, w)
	}

	if err := f.finalize(1); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	merged := output.TagMergedPath(f.basePath, 1)
	n, err := countPcapPackets(merged)
	if err != nil {
		t.Fatalf("reading merged file: %v", err)
	}
	if n != 2 {
		t.Fatalf("merged packet count = %d, want 2", n)
	}

	// deregistered slots must not be double-closed: register one writer,
	// deregister it, close it ourselves, then finalize.
	w, err := output.NewWriter(output.TagShardPath(f.basePath, 0, 2), output.Config{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	f.register(2, 0, w)
	f.deregister(2, 0)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := f.finalize(2); err != nil {
		t.Fatalf("finalize after deregister: %v", err)
	}
}
