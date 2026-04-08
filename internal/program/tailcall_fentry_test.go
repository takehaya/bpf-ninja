package program

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/xdp-ninja/internal/testutil"
)

// tailcallSubfuncSource sets up a tail call chain:
//   xdp_dispatcher → tail call → xdp_leaf → bpf2bpf call → process_in_leaf
const tailcallSubfuncSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} prog_array SEC(".maps");

__attribute__((noinline))
int process_in_leaf(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return 1;
    return 2;
}

SEC("xdp")
int xdp_leaf(struct xdp_md *ctx) {
    return process_in_leaf(ctx);
}

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
    bpf_tail_call(ctx, &prog_array, 0);
    return 2;
}

char _license[] SEC("license") = "GPL";
`

// loadTailcallCollection compiles and loads the tail call test programs.
func loadTailcallCollection(t *testing.T) (dispatcher, leaf *ebpf.Program, progArray *ebpf.Map) {
	t.Helper()
	testutil.SkipIfNotRoot(t)

	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, tailcallSubfuncSource))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}

	var objs struct {
		Dispatcher *ebpf.Program `ebpf:"xdp_dispatcher"`
		Leaf       *ebpf.Program `ebpf:"xdp_leaf"`
		ProgArray  *ebpf.Map     `ebpf:"prog_array"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() {
		_ = objs.Dispatcher.Close()
		_ = objs.Leaf.Close()
		_ = objs.ProgArray.Close()
	})

	if err := objs.ProgArray.Put(uint32(0), uint32(objs.Leaf.FD())); err != nil {
		t.Fatalf("prog_array put: %v", err)
	}

	return objs.Dispatcher, objs.Leaf, objs.ProgArray
}

// setupVethWithXDP creates a veth pair and attaches the given XDP program.
func setupVethWithXDP(t *testing.T, xdpProg *ebpf.Program) (ifaceName string) {
	t.Helper()
	return setupVeth(t, xdpProg, "tcftest0", "tcftest1", "10.99.0.1", "10.99.0.2")
}

// countProbeEvents attaches fentry or fexit to funcName, sends packets,
// and returns the number of perf events received.
func countProbeEvents(t *testing.T, targetProg *ebpf.Program, funcName, iface string, isFexit bool) int {
	t.Helper()
	return countEvents(t, targetProg, funcName, iface, "10.99.0.2", isFexit, nil, 5, 5)
}

// TestBpfTailcallSubfunc verifies that fentry/fexit on a __noinline subfunction
// fires even when the parent program is reached via tail call.
//
// Requires: root, clang, kernel 6.x+ with bpf2bpf + tail call coexistence.
func TestBpfTailcallSubfunc(t *testing.T) {
	dispatcher, leaf, _ := loadTailcallCollection(t)
	iface := setupVethWithXDP(t, dispatcher)

	t.Run("fentry/subfunc_in_leaf", func(t *testing.T) {
		count := countProbeEvents(t, leaf, "process_in_leaf", iface, false)
		if count == 0 {
			t.Fatal("expected events from fentry on subfunc in tail-called program, got 0")
		}
		t.Logf("received %d events", count)
	})

	t.Run("fentry/leaf_entry", func(t *testing.T) {
		count := countProbeEvents(t, leaf, "xdp_leaf", iface, false)
		t.Logf("received %d events (expected 0 for tail call target entry)", count)
	})

	t.Run("fentry/dispatcher_direct", func(t *testing.T) {
		count := countProbeEvents(t, dispatcher, "xdp_dispatcher", iface, false)
		t.Logf("received %d events", count)
	})

	t.Run("fexit/subfunc_in_leaf", func(t *testing.T) {
		count := countProbeEvents(t, leaf, "process_in_leaf", iface, true)
		if count == 0 {
			t.Fatal("expected events from fexit on subfunc in tail-called program, got 0")
		}
		t.Logf("received %d events", count)
	})

	t.Run("fexit/leaf_entry", func(t *testing.T) {
		count := countProbeEvents(t, leaf, "xdp_leaf", iface, true)
		t.Logf("received %d events (expected 0 for tail call target entry)", count)
	})
}
