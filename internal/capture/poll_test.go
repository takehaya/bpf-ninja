package capture

import (
	"errors"
	"os"
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

// submitter returns a function that writes n zeroed MetadataSize records to
// m with the given bpf_ringbuf_output flags (1 = BPF_RB_NO_WAKEUP).
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
	submitter(t, m, 1)(count)
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
	// No Close cleanup: it would wait on a stop that never returns.
	stop, err := r.RunRawShardsFast(func(_ int, _ []byte) error {
		t.Error("unexpected record in idle ring")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	before := voluntarySwitches(t)
	time.Sleep(500 * time.Millisecond)
	switches := voluntarySwitches(t) - before
	stopped := make(chan time.Duration)
	go func() {
		start := time.Now()
		stop()
		stopped <- time.Since(start)
	}()
	select {
	case took := <-stopped:
		t.Logf("idle for 500ms: %d voluntary context switches; stop took %s", switches, took)
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not wake idle shards")
	}
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
	}{{"wakeup", 0}, {"no-wakeup", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			NoWakeup = tc.flags != 0
			t.Cleanup(func() { NoWakeup = false })
			m := newPollTestMap(t)
			submit := submitter(t, m, tc.flags)
			r, err := NewFastShardedReader([]*ebpf.Map{m})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
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
			const count = 600 // More than two batches.
			submit(count)
			stop()
			if err := r.Err(); err != nil {
				t.Fatal(err)
			}
			if got := consumed.Load(); got != count+1 {
				t.Fatalf("consumed %d records, want %d", got, count+1)
			}
		})
	}
}
