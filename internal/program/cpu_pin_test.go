package program

import (
	"bytes"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
	"github.com/takehaya/bpf-ninja/pkg/kunai/dsltest"
)

// maxPinnedCPUs caps how many CPUs a per-CPU ring test visits: the lowest
// ones and the highest, enough to tell slot cpu from slot 0 or cpu+1.
const maxPinnedCPUs = 4

// allowedCPUs returns the CPUs this thread's affinity mask allows, in
// ascending order: all of them, or the lowest maxPinnedCPUs-1 and the
// highest. With fewer than two the test cannot tell slot cpu from slot 0:
// on CI that fails the test (the vimto VMs have two CPUs), elsewhere it
// is logged and the test runs on the one CPU. It never skips, since the
// privileged audit fails unexpected skips.
func allowedCPUs(t *testing.T) []int {
	t.Helper()
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		t.Fatalf("sched_getaffinity: %v", err)
	}
	var cpus []int
	for cpu := 0; cpu < len(set)*64; cpu++ {
		if set.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	switch {
	case len(cpus) == 0:
		t.Fatal("no CPU in the affinity mask")
	case len(cpus) == 1 && os.Getenv("CI") != "":
		t.Fatalf("only CPU %d is allowed; slot selection needs two CPUs to be checked", cpus[0])
	case len(cpus) == 1:
		t.Logf("only CPU %d is allowed; slot selection is checked on it alone", cpus[0])
	case len(cpus) > maxPinnedCPUs:
		cpus = append(slices.Clone(cpus[:maxPinnedCPUs-1]), cpus[len(cpus)-1])
	}
	return cpus
}

// runPinned runs fn on an OS thread bound to cpu and restores the
// thread's affinity before handing it back to the scheduler. If the
// restore fails the thread stays locked, so the runtime retires it when
// the goroutine exits instead of reusing a thread bound to one CPU.
// BPF_PROG_TEST_RUN runs the program, and any fentry/fexit attached to
// it, on the calling CPU with migration disabled, so inside fn
// bpf_get_smp_processor_id() returns cpu.
func runPinned(t *testing.T, cpu int, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	var previous, pinned unix.CPUSet
	if err := unix.SchedGetaffinity(0, &previous); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("sched_getaffinity: %v", err)
	}
	pinned.Set(cpu)
	if err := unix.SchedSetaffinity(0, &pinned); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("pin to CPU %d: %v", cpu, err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &previous); err != nil {
			t.Errorf("restore affinity: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	fn()
}

// checkOnlyShard requires every record in got to sit in shard cpu and
// that shard to hold want records.
func checkOnlyShard(t *testing.T, cpu int, got map[int][]capture.Packet, want int) {
	t.Helper()
	for shard, pkts := range got {
		if shard != cpu {
			t.Errorf("run on CPU %d: %d records in shard %d", cpu, len(pkts), shard)
		}
	}
	if n := len(got[cpu]); n != want {
		t.Errorf("run on CPU %d: %d records in its shard, want %d", cpu, n, want)
	}
}

// checkSlot fails the test when cpu has no ring among slots.
func checkSlot(t *testing.T, cpu, slots int) {
	t.Helper()
	if cpu >= slots {
		t.Fatalf("CPU %d has no slot (%d possible CPUs)", cpu, slots)
	}
}

// collectShards starts a sharded reader over inners and returns a drain
// function that stops it and yields the records per shard index.
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
// pinned to each allowed CPU, with one ring per outer slot and the export
// counters as the CLI wires them, and requires every record in the ring of
// the CPU that ran it, read back under that shard index.
// TestBpfXDPNativePacketUnchanged points every slot at one ring, so it
// cannot tell slot cpu from slot 0.
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
	probe := &Probe{}
	if err := probe.initExportStats(); err != nil {
		t.Fatalf("export stats: %v", err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "bpfninja_ntvcpu",
		Type:         ebpf.XDP,
		Instructions: buildXDPNativeInsns(out, outer.FD(), nil, 0, probe.StatsMap.FD()),
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	frame := dsltest.BuildEthIPv4UDP(t, 1234, 6081, bytes.Repeat([]byte{0xab}, 16))

	for _, cpu := range allowedCPUs(t) {
		checkSlot(t, cpu, len(inners))
		before, err := probe.ExportStats()
		if err != nil {
			t.Fatal(err)
		}
		drain := collectShards(t, inners)
		runPinned(t, cpu, func() {
			for range runs {
				if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
					t.Fatalf("test run on CPU %d: %v", cpu, err)
				}
			}
		})
		got := drain()
		checkOnlyShard(t, cpu, got, runs)
		for i, p := range got[cpu] {
			if !bytes.Equal(p.Data, frame) {
				t.Errorf("CPU %d record %d: bytes differ from the frame", cpu, i)
			}
		}
		after, err := probe.ExportStats()
		if err != nil {
			t.Fatal(err)
		}
		if after.Submitted-before.Submitted != runs || after.ReserveFail+after.LookupMiss+after.CopyFail != 0 {
			t.Errorf("run on CPU %d: export stats %+v (before %+v), want %d more submitted and no failures", cpu, after, before, runs)
		}
	}
}

// TestBpfTracingRecordLandsOnRunningCPU does the same for the single-stage
// fentry and fexit capture (the CLI's default tracing path) on the dummy
// XDP target.
func TestBpfTracingRecordLandsOnRunningCPU(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const runs = 3
	udp := dsltest.BuildEthIPv4UDP(t, 1234, 6081, bytes.Repeat([]byte{0xab}, 32))
	cpus := allowedCPUs(t)
	for _, fexit := range []bool{false, true} {
		t.Run(map[bool]string{false: "fentry", true: "fexit"}[fexit], func(t *testing.T) {
			prog := loadDummyXDP(t)
			probe, err := loadProbe(prog, xdpFuncName, "eth/ipv4/udp", nil, fexit, true)
			if err != nil {
				t.Fatalf("load probe: %v", err)
			}
			defer func() { _ = probe.Close() }()
			for _, cpu := range cpus {
				checkSlot(t, cpu, len(probe.InnerMaps))
				drain := collectShards(t, probe.InnerMaps)
				runPinned(t, cpu, func() {
					for range runs {
						if _, err := prog.Run(&ebpf.RunOptions{Data: udp}); err != nil {
							t.Fatalf("test run on CPU %d: %v", cpu, err)
						}
					}
				})
				if err := probe.Quiesce(); err != nil {
					t.Fatal(err)
				}
				checkOnlyShard(t, cpu, drain(), runs)
			}
		})
	}
}

// TestBpfGatedRecordLandsOnRunningCPU does the same for a gated entry +
// exit probe, for each --emit form. Every record must also carry the CPU
// in its packet id. TestBpfMultiPointGatedTestRun does not pin, so a
// capture that always wrote slot 0 would pass it whenever it ran on CPU 0.
func TestBpfGatedRecordLandsOnRunningCPU(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	const runs = 3
	udp := dsltest.BuildEthIPv4UDP(t, 1234, 6081, bytes.Repeat([]byte{0xab}, 32))
	entry, exit := "eth/ipv4/udp[dport==6081]", "eth/ipv4/udp where action == XDP_PASS"
	cpus := allowedCPUs(t)
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
			for _, cpu := range cpus {
				got := runGatedTestRunOn(t, cpu, entry, exit, tc.emit, repeatFrame(udp, runs), tc.per*runs)
				checkOnlyShard(t, cpu, got, tc.per*runs)
				for i, p := range got[cpu] {
					if id := p.PacketID >> packetIDCPUShift; id != uint64(cpu) {
						t.Errorf("run on CPU %d: record %d packet id %#x names CPU %d", cpu, i, p.PacketID, id)
					}
				}
			}
		})
	}
}
