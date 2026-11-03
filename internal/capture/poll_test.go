package capture

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func newPollTestMap(t *testing.T) *ebpf.Map {
	t.Helper()
	_ = rlimit.RemoveMemlock()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 20})
	if errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("BPF ringbuf unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func processCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

func TestReaderIdleCPU(t *testing.T) {
	m := newPollTestMap(t)
	r, err := NewShardedReader([]*ebpf.Map{m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	stop, err := r.RunRawShards(func(_ int, _ []byte) error {
		t.Error("unexpected record in idle ring")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := processCPU(t)
	time.Sleep(time.Second)
	cpu := processCPU(t) - before
	stop()
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("idle CPU over 1s: %s", cpu)
	// A spinning shard uses about 1 CPU second; allow ample scheduler/GC overhead.
	if cpu > 250*time.Millisecond {
		t.Fatalf("idle reader used %s CPU, want <=250ms", cpu)
	}
}

const rbNoWakeup int32 = 1 // BPF_RB_NO_WAKEUP

// submitter returns a function that writes n zeroed MetadataSize records to
// m with the given bpf_ringbuf_output flags.
func submitter(t *testing.T, m *ebpf.Map, flags int32) func(n int) {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP, License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.StoreMem(asm.RFP, -32, asm.R0, asm.DWord),
			asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
			asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
			asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -32),
			asm.Mov.Imm(asm.R3, MetadataSize),
			asm.Mov.Imm(asm.R4, flags),
			asm.FnRingbufOutput.Call(),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return func(n int) {
		t.Helper()
		for range n {
			retval, _, err := p.Test(make([]byte, 64))
			if err != nil || retval != 0 {
				t.Fatalf("ringbuf output: retval=%d err=%v", retval, err)
			}
		}
	}
}

// stopWithin fails the test instead of the whole suite timing out when a
// stop never returns.
func stopWithin(t *testing.T, stop func(), d time.Duration) time.Duration {
	t.Helper()
	stopped := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		stop()
		stopped <- time.Since(start)
	}()
	select {
	case took := <-stopped:
		return took
	case <-time.After(d):
		t.Fatalf("%s: stop did not return within %s", t.Name(), d)
		return 0
	}
}

func voluntarySwitches(t *testing.T) int64 {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return usage.Nvcsw
}

func TestReaderStopDrainsNoWakeup(t *testing.T) {
	m := newPollTestMap(t)
	// Submit a finite backlog without notifications, before the reader starts.
	const count = 600 // More than two batches.
	submitter(t, m, rbNoWakeup)(count)
	r, err := NewShardedReader([]*ebpf.Map{m})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	var consumed atomic.Uint64
	stop, err := r.RunRawShards(func(_ int, raw []byte) error {
		if len(raw) != MetadataSize {
			t.Errorf("record length = %d, want %d", len(raw), MetadataSize)
		}
		consumed.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	stop()
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != count {
		t.Fatalf("consumed %d records, want %d", got, count)
	}
}

func TestFastReaderStopWhileIdle(t *testing.T) {
	r, err := NewFastShardedReader([]*ebpf.Map{newPollTestMap(t), newPollTestMap(t)})
	if err != nil {
		t.Fatal(err)
	}
	stop, err := r.RunRawShardsFast(func(_ int, _ []byte) error {
		t.Error("unexpected record in idle ring")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
	before := voluntarySwitches(t)
	time.Sleep(500 * time.Millisecond)
	switches := voluntarySwitches(t) - before
	took := stopWithin(t, stop, 5*time.Second)
	t.Logf("idle for 500ms: %d voluntary context switches; stop took %s", switches, took)
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
	// A 1 ms poll would wake each of the two shards about 500 times.
	if switches > 200 {
		t.Fatalf("idle shards switched %d times in 500ms, want <=200", switches)
	}
}

func TestFastReaderStopKeepsRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags int32
	}{{"wakeup", 0}, {"no-wakeup", rbNoWakeup}} {
		t.Run(tc.name, func(t *testing.T) {
			NoWakeup = tc.flags != 0
			t.Cleanup(func() { NoWakeup = false })
			m := newPollTestMap(t)
			submit := submitter(t, m, tc.flags)
			r, err := NewFastShardedReader([]*ebpf.Map{m})
			if err != nil {
				t.Fatal(err)
			}
			var consumed atomic.Uint64
			stop, err := r.RunRawShardsFast(func(_ int, raw []byte) error {
				if len(raw) != MetadataSize {
					t.Errorf("record length = %d, want %d", len(raw), MetadataSize)
				}
				consumed.Add(1)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
			// A shard blocked on an idle ring must see a record before stop.
			time.Sleep(50 * time.Millisecond)
			submit(1)
			deadline := time.Now().Add(5 * time.Second)
			for consumed.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if consumed.Load() != 1 {
				t.Fatalf("consumed %d records before stop, want 1", consumed.Load())
			}
			// Everything submitted before stop is consumed by stop.
			const count = 600
			submit(count)
			stopWithin(t, stop, 5*time.Second)
			if err := r.Err(); err != nil {
				t.Fatal(err)
			}
			if got := consumed.Load(); got != count+1 {
				t.Fatalf("consumed %d records, want %d", got, count+1)
			}
		})
	}
}

// A submit committed while the shard is inside a batch sees the old consumer
// position and sends no wakeup; only epoll's re-poll of the level-triggered
// ring fd finds it. Delivery is checked before stop, which would drain it.
// The wait bound is stretched so that it cannot deliver the records instead.
func TestFastReaderStaleConsumer(t *testing.T) {
	wait := shardWaitMs
	shardWaitMs = 60_000
	t.Cleanup(func() { shardWaitMs = wait })
	m := newPollTestMap(t)
	submit := submitter(t, m, 0)
	r, err := NewFastShardedReader([]*ebpf.Map{m})
	if err != nil {
		t.Fatal(err)
	}
	arrived, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var consumed atomic.Uint64
	stop, err := r.RunRawShardsFast(func(_ int, _ []byte) error {
		once.Do(func() { close(arrived); <-release })
		consumed.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
	unpark := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unpark) // runs before the stop cleanup
	time.Sleep(20 * time.Millisecond)
	submit(1)
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("first record not seen")
	}
	const more = 100
	submit(more)
	unpark()
	deadline := time.Now().Add(3 * time.Second)
	for consumed.Load() < 1+more && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := consumed.Load()
	stopWithin(t, stop, 5*time.Second)
	if got != 1+more {
		t.Fatalf("consumed %d before stop, want %d (after stop: %d)", got, 1+more, consumed.Load())
	}
}

// A record the probe submits below its wakeup threshold carries
// BPF_RB_NO_WAKEUP; a shard blocked on an idle ring must still read it
// within the wait bound, without stop.
func TestFastReaderBoundedWait(t *testing.T) {
	m := newPollTestMap(t)
	submit := submitter(t, m, rbNoWakeup)
	r, err := NewFastShardedReader([]*ebpf.Map{m})
	if err != nil {
		t.Fatal(err)
	}
	var consumed atomic.Uint64
	stop, err := r.RunRawShardsFast(func(int, []byte) error { consumed.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
	time.Sleep(20 * time.Millisecond) // let the shard block
	start := time.Now()
	submit(1)
	for consumed.Load() == 0 && time.Since(start) < 2*time.Second {
		time.Sleep(time.Millisecond)
	}
	took := time.Since(start)
	t.Logf("unsignalled record read after %s (bound %d ms)", took, shardWaitMs)
	if consumed.Load() != 1 {
		t.Fatalf("unsignalled record not read within %s without stop", took)
	}
	// Three times the 50 ms bound, fixed so that a longer bound fails here.
	if limit := 150 * time.Millisecond; took > limit {
		t.Fatalf("unsignalled record read after %s, want within %s", took, limit)
	}
}

// Stop must wake a blocked shard that has a backlog the kernel never
// signalled, drain it, hand it to the sink, and count it as drained at
// stop. The packet sink sees the batch only in the flush after ReadBatch.
// The wait bound is stretched so the backlog is still unread at stop, as
// records below the wakeup threshold are when stop comes first.
func TestFastReaderStopDrainsBacklog(t *testing.T) {
	wait := shardWaitMs
	shardWaitMs = 60_000
	t.Cleanup(func() { shardWaitMs = wait })
	for _, tc := range []struct {
		name string
		run  func(*FastShardedReader, *atomic.Uint64) (func(), error)
	}{
		{"raw", func(r *FastShardedReader, n *atomic.Uint64) (func(), error) {
			return r.RunRawShardsFast(func(int, []byte) error { n.Add(1); return nil })
		}},
		{"packets", func(r *FastShardedReader, n *atomic.Uint64) (func(), error) {
			return r.RunShardsFast(func(_ int, p []Packet) error { n.Add(uint64(len(p))); return nil })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newPollTestMap(t)
			submit := submitter(t, m, rbNoWakeup) // NoWakeup stays false: no poll
			r, err := NewFastShardedReader([]*ebpf.Map{m})
			if err != nil {
				t.Fatal(err)
			}
			var written atomic.Uint64
			stop, err := tc.run(r, &written)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
			time.Sleep(20 * time.Millisecond)
			const count = 300
			submit(count)
			time.Sleep(100 * time.Millisecond)
			if got := written.Load(); got != 0 {
				t.Fatalf("wrote %d unsignalled records before stop, want 0", got)
			}
			stopWithin(t, stop, 5*time.Second)
			if err := r.Err(); err != nil {
				t.Fatal(err)
			}
			got, consumed, drained := written.Load(), r.Stats().Consumed.Load(), r.Stats().DrainedAtStop.Load()
			if got != count || consumed != count || drained != count {
				t.Fatalf("wrote %d, consumed %d, drained at stop %d, want %d", got, consumed, drained, count)
			}
		})
	}
}

// A new session on a drained ring must pass Barrier without a new record:
// each shard acknowledges once before its first wait.
func TestFastReaderBarrierReusedRing(t *testing.T) {
	m := newPollTestMap(t)
	submitter(t, m, 0)(3)
	first, err := NewFastShardedReader([]*ebpf.Map{m})
	if err != nil {
		t.Fatal(err)
	}
	stop, err := first.RunRawShardsFast(func(int, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	stopWithin(t, stop, 5*time.Second)
	if n := first.Stats().Consumed.Load(); n != 3 {
		t.Fatalf("first session consumed %d, want 3", n)
	}
	r, err := NewFastShardedReader([]*ebpf.Map{m})
	if err != nil {
		t.Fatal(err)
	}
	stop, err = r.RunRawShardsFast(func(int, []byte) error { t.Error("unexpected record"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
	done := r.Barrier()
	ok := false
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if ok, err = done(); ok || err != nil {
			break
		}
	}
	if err != nil || !ok {
		t.Fatalf("Barrier on a drained, reused ring: done=%v err=%v after 300ms", ok, err)
	}
}

func TestFastReaderNoFDLeak(t *testing.T) {
	maps := []*ebpf.Map{newPollTestMap(t), newPollTestMap(t), newPollTestMap(t)}
	fds := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := fds()
	for range 5 {
		r, err := NewFastShardedReader(maps)
		if err != nil {
			t.Fatal(err)
		}
		stop, err := r.RunRawShardsFast(func(int, []byte) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stopWithin(t, stop, 5*time.Second) })
		time.Sleep(5 * time.Millisecond)
		stopWithin(t, stop, 5*time.Second)
		if err := r.Err(); err != nil {
			t.Fatal(err)
		}
	}
	if after := fds(); after != before {
		t.Fatalf("open fds: %d before, %d after 5 sessions", before, after)
	}
}
