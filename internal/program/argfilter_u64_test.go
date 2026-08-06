package program

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture"
	"github.com/takehaya/bpf-ninja/internal/filter"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// Regression coverage for issue #96: --arg-filter on a u64 argument whose
// value does not fit in 32 bits, read via fentry on a bpf2bpf subprogram.
// The subprogram signature mirrors the report:
// (struct xdp_md *ctx, __u64 imsi, __u32 teid). The IMSI uses the
// ITU-reserved test PLMN (MCC 999) so it cannot collide with a live
// subscriber, while still not fitting in 32 bits.
//
// imsi/teid come from volatile globals so the call site passes runtime
// values, and the callee pins its args to the ABI with barrier_var the
// same way keep_args.h does — without that, clang -O2 is free to drop the
// dead args (or the whole call) and the trampoline-saved registers would
// hold stale values, which is invisible to bpf-ninja (see keep_args.h).
const argFilterU64Source = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define barrier_var(var) asm volatile("" : : "r"(var))

volatile __u64 g_imsi = 999990000000021ULL;
volatile __u32 g_teid = 100;

__attribute__((noinline))
int bearer_capture_point(struct xdp_md *ctx, __u64 imsi, __u32 teid) {
    barrier_var(ctx);
    barrier_var(imsi);
    barrier_var(teid);
    return 0;
}

SEC("xdp")
int xdp_u64_argtest(struct xdp_md *ctx) {
    bearer_capture_point(ctx, g_imsi, g_teid);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
`

const testIMSI = uint64(999990000000021)

// countEventsTestRun is countEvents without the veth+ping dependency:
// it attaches the probe, fires the target via BPF_PROG_TEST_RUN, and
// counts capture events from the sharded ringbuf. Works on kernels
// whose test image has no veth driver (vimto CI matrix).
func countEventsTestRun(t *testing.T, targetProg *ebpf.Program, funcName string, argFilters []filter.ArgFilter, runs int) int {
	t.Helper()

	probe, err := LoadEntry(targetProg, funcName, "", argFilters, false)
	if err != nil {
		t.Fatalf("load probe (%s): %v", funcName, err)
	}
	defer func() { _ = probe.Close() }()

	sr, err := capture.NewShardedReader(probe.InnerMaps)
	if err != nil {
		t.Fatalf("sharded reader: %v", err)
	}

	var count atomic.Int64
	sink := func(shardIdx int, pkts []capture.Packet) error {
		count.Add(int64(len(pkts)))
		return nil
	}
	stop, err := sr.RunShards(sink)
	if err != nil {
		t.Fatalf("RunShards: %v", err)
	}
	defer stop()

	in := make([]byte, 64)
	for range runs {
		if _, err := targetProg.Run(&ebpf.RunOptions{Data: in}); err != nil {
			t.Fatalf("test-run target: %v", err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if int(count.Load()) >= runs {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return int(count.Load())
}

// imsiFilter builds a single-condition ArgFilter on imsi from BTF params.
func imsiFilter(t *testing.T, prog *ebpf.Program, funcName string, op filter.ArgFilterOp, value uint64, maxValue ...uint64) []filter.ArgFilter {
	t.Helper()
	params, err := attach.GetFuncParams(prog, funcName)
	if err != nil {
		t.Fatalf("GetFuncParams(%s): %v", funcName, err)
	}
	for _, p := range params {
		if p.Name != "imsi" {
			continue
		}
		if p.Size != 8 {
			t.Fatalf("imsi param size = %d, want 8", p.Size)
		}
		f := filter.ArgFilter{
			ParamName:  p.Name,
			ParamIndex: p.Index,
			ParamSize:  p.Size,
			Signed:     p.Signed,
			Op:         op,
			Value:      value,
		}
		if len(maxValue) > 0 {
			f.MaxValue = maxValue[0]
		}
		return []filter.ArgFilter{f}
	}
	t.Fatalf("imsi param not found in %s (BTF)", funcName)
	return nil
}

// TestBpfArgFilterU64Subprog pins exact-match, set-style-exactness and
// range semantics for a >2^32 u64 argument on a bpf2bpf-subprogram fentry.
func TestBpfArgFilterU64Subprog(t *testing.T) {
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, argFilterU64Source))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	var objs struct {
		XDP *ebpf.Program `ebpf:"xdp_u64_argtest"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = objs.XDP.Close() })
	prog := objs.XDP

	const fn = "bearer_capture_point"

	if got := countEventsTestRun(t, prog, fn, nil, 3); got == 0 {
		t.Fatal("expected events without filter, got 0")
	}

	tests := []struct {
		name    string
		filters []filter.ArgFilter
		wantHit bool
	}{
		{"exact_hit", imsiFilter(t, prog, fn, filter.OpEqual, testIMSI), true},
		{"exact_miss", imsiFilter(t, prog, fn, filter.OpEqual, testIMSI+1), false},
		{"tight_range_hit", imsiFilter(t, prog, fn, filter.OpRange, testIMSI-21, testIMSI+78), true},
		{"range_miss_below", imsiFilter(t, prog, fn, filter.OpRange, testIMSI+1, testIMSI+100), false},
		{"magnitude_hit", imsiFilter(t, prog, fn, filter.OpGreaterEqual, 900000000000000), true},
		{"magnitude_miss", imsiFilter(t, prog, fn, filter.OpGreaterEqual, 1000000000000000), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countEventsTestRun(t, prog, fn, tt.filters, 3)
			if tt.wantHit && got == 0 {
				t.Fatalf("expected events with %s, got 0", tt.filters[0].String())
			}
			if !tt.wantHit && got != 0 {
				t.Fatalf("expected 0 events with %s, got %d", tt.filters[0].String(), got)
			}
			t.Logf("%d events (%s)", got, tt.filters[0].String())
		})
	}
}
