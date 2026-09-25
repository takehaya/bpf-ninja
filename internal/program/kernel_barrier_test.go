package program

import (
	"fmt"
	"golang.org/x/sys/unix"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Keep an actual non-sleepable invocation alive after reserving a BUSY record.
// Userspace releases it only after proving Quiesce/BlockTag has not returned.
const heldProducerSource = `
#include <linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 65536); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 3); __type(key, __u32); __type(value, __u32); } control SEC(".maps");
static void *(*lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static void *(*reserve)(void *, __u64, __u64) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*submit)(void *, __u64) = (void *)BPF_FUNC_ringbuf_submit;
static long (*loop)(__u32, void *, void *, __u64) = (void *)BPF_FUNC_loop;
static __u64 (*now)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long await_release(__u32 index, void *ctx) {
 now();
 __u32 key=1; volatile __u32 *release=lookup(&control,&key);
 return release && *release;
}
static long await_round(__u32 index, void *ctx) {
 loop(8388608,await_release,0,0);
 return await_release(0,0);
}
SEC("xdp") int held_producer(struct xdp_md *ctx) {
 __u64 *record=reserve(&events,32,0); if (!record) return 0;
 record[0]=record[1]=record[2]=record[3]=0;
 __u32 key=0; volatile __u32 *entered=lookup(&control,&key);
 if (entered) *entered=1;
 loop(8,await_round,0,0);
 key=1; volatile __u32 *release=lookup(&control,&key);
 if (!release || !*release) { key=2; __u32 *expired=lookup(&control,&key); if(expired) *expired=1; }
 submit(record,0); return 2;
}
char _license[] SEC("license")="GPL";
`

func TestBpfKernelBarrierWaitsForBusyRecord(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	// The controller must remain runnable while the non-sleepable producer
	// occupies its CPU. Keep them on distinct CPUs from the allowed mask.
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		t.Fatal(err)
	}
	var cpus []int
	for cpu := 0; cpu < 1024; cpu++ {
		if allowed.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) < 2 {
		t.Fatal("controlled in-flight producer test requires two allowed CPUs")
	}
	var controllerCPU, producerCPU unix.CPUSet
	controllerCPU.Set(cpus[0])
	producerCPU.Set(cpus[1])

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, heldProducerSource))
	if err != nil {
		t.Fatal(err)
	}
	for _, fast := range []bool{false, true} {
		for _, tag := range []bool{false, true} {
			t.Run(fmt.Sprintf("fast=%v/tag=%v", fast, tag), func(t *testing.T) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var previous unix.CPUSet
				if err := unix.SchedGetaffinity(0, &previous); err != nil {
					t.Fatal(err)
				}
				if err := unix.SchedSetaffinity(0, &controllerCPU); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := unix.SchedSetaffinity(0, &previous); err != nil {
						t.Error(err)
					}
				}()

				col, err := ebpf.NewCollection(spec)
				if err != nil {
					t.Fatal(err)
				}
				defer col.Close()
				ring, ctrl := col.Maps["events"], col.Maps["control"]
				outer, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: &ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 65536}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = outer.Close() }()
				if err := outer.Update(uint32(0), ring, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				probe := &Probe{EventsMap: outer, InnerMaps: []*ebpf.Map{ring}}
				if _, err := probe.initTagBarrier(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = probe.closedTags.Close() }()
				var written atomic.Uint64
				sink := func(_ int, p []capture.Packet) error { written.Add(uint64(len(p))); return nil }
				var stop func()
				var readErr func() error
				if fast {
					r, e := capture.NewFastShardedReader(probe.InnerMaps)
					if e != nil {
						t.Fatal(e)
					}
					stop, err = r.RunShardsFast(sink)
					readErr = r.Err
				} else {
					r, e := capture.NewShardedReader(probe.InnerMaps)
					if e != nil {
						t.Fatal(e)
					}
					stop, err = r.RunShards(sink)
					readErr = r.Err
				}
				if err != nil {
					t.Fatal(err)
				}
				runDone := make(chan error, 1)
				go func() {
					runtime.LockOSThread()
					defer runtime.UnlockOSThread()
					var previous unix.CPUSet
					if err := unix.SchedGetaffinity(0, &previous); err != nil {
						runDone <- err
						return
					}
					if err := unix.SchedSetaffinity(0, &producerCPU); err != nil {
						runDone <- err
						return
					}
					defer func() { _ = unix.SchedSetaffinity(0, &previous) }()
					_, err := col.Programs["held_producer"].Run(&ebpf.RunOptions{Data: make([]byte, 64)})
					runDone <- err
				}()
				released := false
				release := func() {
					if !released {
						released = true
						if e := ctrl.Update(uint32(1), uint32(1), ebpf.UpdateAny); e != nil {
							t.Error(e)
						}
					}
				}
				defer func() { release(); stop() }()
				deadline := time.Now().Add(5 * time.Second)
				for {
					var entered uint32
					if e := ctrl.Lookup(uint32(0), &entered); e != nil {
						t.Fatal(e)
					}
					if entered == 1 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("producer never reserved")
					}
					time.Sleep(time.Millisecond)
				}
				barrierDone := make(chan error, 1)
				barrierStarted := make(chan struct{})
				go func() {
					close(barrierStarted)
					if tag {
						barrierDone <- probe.BlockTag(7)
					} else {
						barrierDone <- probe.Quiesce()
					}
				}()
				<-barrierStarted
				select {
				case err := <-barrierDone:
					var expired uint32
					_ = ctrl.Lookup(uint32(2), &expired)
					t.Fatalf("barrier returned with a BUSY record: %v, expired=%d written=%d", err, expired, written.Load())
				case <-time.After(50 * time.Millisecond):
				}
				if written.Load() != 0 {
					t.Fatal("BUSY record delivered before submit")
				}
				release()
				select {
				case err := <-runDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("producer did not finish")
				}
				select {
				case err := <-barrierDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("barrier did not finish")
				}
				var expired uint32
				if err := ctrl.Lookup(uint32(2), &expired); err != nil {
					t.Fatal(err)
				}
				if expired != 0 {
					t.Fatal("producer exhausted its hold loop before release")
				}
				stop()
				if err := readErr(); err != nil {
					t.Fatal(err)
				}
				if written.Load() != 1 {
					t.Fatalf("written=%d want exactly one committed record", written.Load())
				}
			})
		}
	}
}
