package program

import (
	"bytes"
	"runtime"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

// maxPinnedCPUs caps how many CPUs a per-CPU ring test visits; the first
// few are enough to tell slot cpu from slot 0 or cpu+1.
const maxPinnedCPUs = 4

// allowedCPUs returns the CPUs this thread's affinity mask allows, at
// most maxPinnedCPUs of them, in ascending order.
func allowedCPUs(t *testing.T) []int {
	t.Helper()
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		t.Fatalf("sched_getaffinity: %v", err)
	}
	var cpus []int
	for cpu := 0; cpu < len(set)*64 && len(cpus) < maxPinnedCPUs; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) == 0 {
		t.Fatal("no CPU in the affinity mask")
	}
	if len(cpus) == 1 {
		// Not a skip: the privileged audit fails unexpected skips, and one
		// CPU still checks that the record reaches that CPU's ring.
		t.Logf("only CPU %d is allowed; slot selection is checked on it alone", cpus[0])
	}
	return cpus
}

// runPinned runs fn on an OS thread bound to cpu and restores the
// thread's affinity before handing it back to the scheduler.
// BPF_PROG_TEST_RUN runs the program, and any fentry/fexit attached to
// it, on the calling CPU with migration disabled, so inside fn
// bpf_get_smp_processor_id() returns cpu.
func runPinned(t *testing.T, cpu int, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var previous, pinned unix.CPUSet
	if err := unix.SchedGetaffinity(0, &previous); err != nil {
		t.Fatalf("sched_getaffinity: %v", err)
	}
	pinned.Set(cpu)
	if err := unix.SchedSetaffinity(0, &pinned); err != nil {
		t.Fatalf("pin to CPU %d: %v", cpu, err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &previous); err != nil {
			t.Errorf("restore affinity: %v", err)
		}
	}()
	fn()
}

// collectShards starts a sharded reader over inners and returns a stop
// function that drains it and yields the records per shard index.
// Call it before runPinned: RunShards places its reader goroutines from
// the calling thread's affinity mask.
func collectShards(t *testing.T, inners []*ebpf.Map) func() map[int][]capture.Packet {
	t.Helper()
	sr, err := capture.NewShardedReader(inners)
	if err != nil {
		t.Fatalf("sharded reader: %v", err)
	}
	var mu sync.Mutex
	got := map[int][]capture.Packet{}
	sink := func(shardIdx int, pkts []capture.Packet) error {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range pkts {
			p.Data = append([]byte(nil), p.Data...) // ring memory is reused after the sink returns
			got[shardIdx] = append(got[shardIdx], p)
		}
		return nil
	}
	stop, err := sr.RunShards(sink)
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	t.Cleanup(stop) // a Fatalf before the returned function runs; stop is idempotent
	return func() map[int][]capture.Packet {
		stop()
		if err := sr.Err(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

// TestBpfXDPNativeRecordLandsOnRunningCPU runs the native XDP program
// pinned to each allowed CPU, with one ring per outer slot as the CLI
// creates them, and requires every record in the ring of the CPU that
// ran it, read back under that shard index. TestBpfXDPNativePacketUnchanged
// points every slot at one ring, so it cannot tell slot cpu from slot 0.
func TestBpfXDPNativeRecordLandsOnRunningCPU(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const runs = 3
	out, err := compileFilter("eth/ipv4/udp", true, false, ebpf.XDP)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	outer, inners, err := createShardedRingbuf("xdpcpu")
	if err != nil {
		t.Fatalf("sharded ringbuf: %v", err)
	}
	t.Cleanup(func() {
		_ = outer.Close()
		for _, m := range inners {
			_ = m.Close()
		}
	})
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "bpfninja_ntvcpu",
		Type:         ebpf.XDP,
		Instructions: buildXDPNativeInsns(out, outer.FD(), nil, 0, 0),
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, bytes.Repeat([]byte{0xab}, 16))

	for _, cpu := range allowedCPUs(t) {
		if cpu >= len(inners) {
			t.Fatalf("CPU %d has no slot (%d possible CPUs)", cpu, len(inners))
		}
		stop := collectShards(t, inners)
		runPinned(t, cpu, func() {
			for range runs {
				if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
					t.Fatalf("test run on CPU %d: %v", cpu, err)
				}
			}
		})
		got := stop()
		for shard, pkts := range got {
			if shard != cpu {
				t.Errorf("run on CPU %d: %d records in shard %d", cpu, len(pkts), shard)
			}
		}
		if n := len(got[cpu]); n != runs {
			t.Errorf("run on CPU %d: %d records in its shard, want %d", cpu, n, runs)
		}
		for i, p := range got[cpu] {
			if !bytes.Equal(p.Data, frame) {
				t.Errorf("CPU %d record %d: bytes differ from the frame", cpu, i)
			}
		}
	}
}

// TestBpfGatedRecordLandsOnRunningCPU does the same for the tracing
// capture: a gated entry + exit probe on the dummy XDP target, test-run
// pinned to each allowed CPU, for each --emit form. Every record must be
// in that CPU's shard and carry the CPU in the top 16 bits of its packet
// id (cpu << 48 | seq, set for every --emit form). TestBpfMultiPointGatedTestRun does not pin, so a capture
// that always wrote slot 0 would pass it whenever it ran on CPU 0.
func TestBpfGatedRecordLandsOnRunningCPU(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const runs = 3
	udp := dsltest.BuildEthIPv4UDP(t, 1234, 6081, bytes.Repeat([]byte{0xab}, 32))
	entry, exit := "eth/ipv4/udp[dport==6081]", "eth/ipv4/udp where action == XDP_PASS"
	for _, tc := range []struct {
		name string
		emit Emit
		per  int
	}{
		{"both", EmitBoth, 2},
		{"entry-only", EmitEntry, 1},
		{"exit-only", EmitExit, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cpu := range allowedCPUs(t) {
				got := runGatedTestRunOn(t, cpu, entry, exit, tc.emit, repeatFrame(udp, runs), tc.per*runs)
				for shard, pkts := range got {
					if shard != cpu {
						t.Errorf("run on CPU %d: %d records in shard %d", cpu, len(pkts), shard)
					}
					for i, p := range pkts {
						if p.PacketID>>48 != uint64(cpu) {
							t.Errorf("run on CPU %d: record %d packet id %#x names CPU %d", cpu, i, p.PacketID, p.PacketID>>48)
						}
					}
				}
			}
		})
	}
}
