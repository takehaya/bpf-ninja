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

func TestReaderStopDrainsNoWakeup(t *testing.T) {
	m := newPollTestMap(t)
	// Submit a finite backlog without notifications, before the reader starts.
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
			asm.Mov.Imm(asm.R4, 1), // BPF_RB_NO_WAKEUP
			asm.FnRingbufOutput.Call(),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	const count = 600 // More than two batches.
	for range count {
		retval, _, err := p.Test(make([]byte, 64))
		if err != nil || retval != 0 {
			t.Fatalf("ringbuf output: retval=%d err=%v", retval, err)
		}
	}
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
