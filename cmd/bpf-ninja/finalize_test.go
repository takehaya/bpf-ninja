package main

import (
	"errors"
	"fmt"
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
	f := newTagFinalizer(base, output.Config{}, shards)
	f.begin = func(uint32) (func() (bool, error), error) { return func() (bool, error) { return true, nil }, nil }
	return f
}

// An arbitrarily delayed reader must prevent the stop sign and ack, even
// when there is no observed activity for many lifecycle polls.
func TestStepWaitsForAcknowledgement(t *testing.T) {
	f := newTestFinalizer(t, 2)
	ready := false
	calls := 0
	f.begin = func(tag uint32) (func() (bool, error), error) {
		calls++
		return func() (bool, error) { return ready, nil }, nil
	}
	st := f.stateFor(7)
	if done := f.step([]uint32{7}); len(done) != 0 || calls != 0 {
		t.Fatal("blocked live tag")
	}
	for range 100 {
		if done := f.step(nil); len(done) != 0 || st.finalized.Load() {
			t.Fatal("quiet poll replaced barrier")
		}
	}
	if calls != 1 {
		t.Fatalf("barrier started %d times", calls)
	}
	// Once the tombstone exists, a re-add must not cancel or reopen the tag.
	f.step([]uint32{7})
	ready = true
	if done := f.step([]uint32{7}); len(done) != 1 || done[0] != 7 {
		t.Fatalf("ack=%v", done)
	}
	if !st.finalized.Load() {
		t.Fatal("stop sign absent after acknowledgement")
	}
	if done := f.step(nil); len(done) != 1 {
		t.Fatal("merge retry lost")
	}
	f.markMerged(7)
	if done := f.step(nil); len(done) != 0 {
		t.Fatal("merged tag retried")
	}
}

func TestStepUnionSeenAndTagZero(t *testing.T) {
	f := newTestFinalizer(t, 1)
	f.step([]uint32{9})
	f.stateFor(0)
	if done := f.step(nil); len(done) != 1 || done[0] != 9 {
		t.Fatalf("done=%v", done)
	}
	f.markMerged(9)
	if done := f.step(nil); len(done) != 0 {
		t.Fatal("tag zero finalized")
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

// A failed merge must leave the tag un-merged (retried by step, not
// skipped at shutdown) and succeed once the cause clears.
func TestFinalizeFailureRetries(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	f := newTestFinalizer(t, 1)
	f.basePath = filepath.Join(missing, "out.pcap")
	f.stateFor(4)
	f.step(nil)
	f.step(nil) // stop sign
	if done := f.step(nil); len(done) != 1 || done[0] != 4 {
		t.Fatalf("step = %v, want [4]", done)
	}

	if err := f.finalize(4); err == nil {
		t.Fatal("finalize into a missing directory succeeded")
	}
	if got := f.mergedTags(); len(got) != 0 {
		t.Fatalf("failed merge marked as merged: %v", got)
	}
	if done := f.step(nil); len(done) != 1 || done[0] != 4 {
		t.Fatalf("failed tag not retried: %v", done)
	}

	if err := os.Mkdir(missing, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := f.finalize(4); err != nil {
		t.Fatalf("finalize after the cause cleared: %v", err)
	}
	if got := f.mergedTags(); len(got) != 1 || !got[4] {
		t.Fatalf("mergedTags = %v, want {4}", got)
	}
	if done := f.step(nil); len(done) != 0 {
		t.Fatalf("merged tag still retried: %v", done)
	}
}

// closeAll must flush+close writers still registered (a tag caught
// between its stop sign and its close+merge at shutdown) and leave the
// registry empty so nothing is closed twice.
func TestCloseAllFlushesRemaining(t *testing.T) {
	f := newTestFinalizer(t, 1)
	path := output.TagShardPath(f.basePath, 0, 6)
	w, err := output.NewWriter(path, output.Config{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteBatch(testutilPackets()); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	f.register(6, 0, w)

	if err := f.closeAll(); err != nil {
		t.Fatal(err)
	}
	n, err := countPcapPackets(path)
	if err != nil {
		t.Fatalf("reading shard after closeAll: %v", err)
	}
	if n != 2 {
		t.Fatalf("shard packet count = %d, want 2 (buffer not flushed)", n)
	}
	// Registry drained: finalize must not double-close.
	if err := f.finalize(6); err != nil {
		t.Fatalf("finalize after closeAll: %v", err)
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

// Buffered bytes lost on flush must never turn into a zero-packet ack on retry.
func TestFinalizeFlushFailureNeverAcknowledges(t *testing.T) {
	f := newTestFinalizer(t, 1)
	w, err := output.NewWriter("/dev/full", output.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteBatch(testutilPackets()); err != nil {
		t.Fatal(err)
	}
	f.register(23, 0, w)
	for attempt := range 3 {
		if err := f.finalize(23); err == nil {
			t.Fatalf("attempt %d acknowledged failed flush", attempt)
		}
		if f.isMerged(23) {
			t.Fatal("failed tag marked merged")
		}
		if _, err := os.Stat(output.TagMergedPath(f.basePath, 23)); !os.IsNotExist(err) {
			t.Fatalf("ack exists or unexpected stat error: %v", err)
		}
	}
}

func TestCloseAllFailureRemainsTerminal(t *testing.T) {
	f := newTestFinalizer(t, 1)
	w, err := output.NewWriter("/dev/full", output.Config{})
	if err != nil {
		t.Fatal(err)
	}
	f.register(7, 0, w)
	for range 3 {
		if err := f.closeAll(); err == nil {
			t.Fatal("shutdown lost output failure")
		}
		if err := f.finalize(7); err == nil {
			t.Fatal("shutdown failure became successful finalize")
		}
	}
	lc := newCapLifecycle(nil, f, nil, f.basePath, true)
	if !lc.tick() {
		t.Fatal("terminal failure did not stop capture")
	}
	if lc.exitReady(nil, nil) {
		t.Fatal("terminal failure treated as successful cap exit")
	}
}

func TestStepBarrierFailureNeverAcknowledges(t *testing.T) {
	for _, atStart := range []bool{false, true} {
		f := newTestFinalizer(t, 1)
		failure := fmt.Errorf("injected barrier failure")
		f.begin = func(uint32) (func() (bool, error), error) {
			if atStart {
				return nil, failure
			}
			return func() (bool, error) { return false, failure }, nil
		}
		f.stateFor(7)
		for range 5 {
			if done := f.step(nil); len(done) != 0 {
				t.Fatal("failed barrier acknowledged")
			}
		}
		if !errors.Is(f.Err(), failure) {
			t.Fatalf("error=%v", f.Err())
		}
		if err := f.finalize(7); !errors.Is(err, failure) {
			t.Fatalf("finalize=%v", err)
		}
		if _, err := os.Stat(output.TagMergedPath(f.basePath, 7)); !os.IsNotExist(err) {
			t.Fatal("ack exists")
		}
	}
}
