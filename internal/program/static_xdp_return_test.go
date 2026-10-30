package program

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/takehaya/bpf-ninja/internal/attach"
	"github.com/takehaya/bpf-ninja/internal/capture/fastrb"
	"github.com/takehaya/bpf-ninja/internal/testutil"
)

// A discarded static prototype cannot use the four-parameter BTF return slot.
// This function's return differs from every argument.
const staticXDPReturnSource = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct policy { __u32 action; };
// Prevent interprocedural constant propagation from removing arguments/return.
volatile __u32 site = 24;
volatile __u64 status = 5;
__attribute__((noinline))
static int static_hook4(struct xdp_md *ctx, __u32 site, const struct policy *value, __u64 status) {
    asm volatile("" : : "r"(ctx), "r"(site), "r"(value), "r"(status));
    return (int)status + (int)site == 29 ? XDP_PASS : XDP_DROP;
}
SEC("xdp")
int static4_target(struct xdp_md *ctx) {
    struct policy p = { .action = 7 };
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    if (data + 1 > end) return XDP_ABORTED;
    int r = static_hook4(ctx, site, *(__u8 *)data ? 0 : &p, status);
    return r == XDP_PASS ? XDP_PASS : XDP_DROP;
}
char _license[] SEC("license") = "GPL";
`

func TestBpfStaticXDPReturnAction(t *testing.T) {
	testutil.SkipIfNotRoot(t)
	spec, err := ebpf.LoadCollectionSpec(testutil.CompileBPFSource(t, staticXDPReturnSource))
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	target := coll.Programs["static4_target"]
	fallback, err := staticXDPNeedsProbeRead(target, "static_hook4", ebpf.AttachTraceFExit, attach.FuncAvailability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("four-argument static fexit probe_read=%v", fallback)
	for _, mode := range []string{"exit", "gated"} {
		for _, expr := range []string{"eth", "eth where action == XDP_PASS", "eth where action == XDP_DROP"} {
			t.Run(mode+"/"+expr, func(t *testing.T) {
				stages := []Stage{{Expr: expr, IsFexit: true}}
				if mode == "gated" {
					stages = []Stage{{Expr: "eth"}, {Expr: expr, IsFexit: true}}
				}
				probe, err := LoadMultiPoint([]attach.Target{{Program: target, FuncName: "static_hook4", Type: ebpf.XDP}}, stages, nil, true, nil, EmitBoth)
				if err != nil {
					t.Fatalf("load capture: %+v", err)
				}
				defer func() { _ = probe.Close() }()
				ret, err := target.Run(&ebpf.RunOptions{Data: make([]byte, 64)})
				if err != nil || ret != 2 {
					t.Fatalf("target returned %d, err=%v", ret, err)
				}
				if err := probe.Quiesce(); err != nil {
					t.Fatal(err)
				}
				var modes [2]int
				for _, m := range probe.InnerMaps {
					rd, err := fastrb.New(m.FD(), int(m.MaxEntries()))
					if err != nil {
						t.Fatal(err)
					}
					rd.ReadBatch(func(rec []byte) {
						if len(rec) < metadataSize || rec[12] > 1 {
							t.Errorf("invalid capture record: %x", rec)
							return
						}
						modes[rec[12]]++
						if action := binary.NativeEndian.Uint32(rec[8:12]); action != 2 {
							t.Errorf("mode=%d action=%d, want hook return XDP_PASS (2)", rec[12], action)
						}
					})
					_ = rd.Close()
				}
				want := [2]int{0, 1}
				if mode == "gated" {
					want[0] = 1
				}
				if expr == "eth where action == XDP_DROP" {
					want = [2]int{}
				}
				if modes != want {
					t.Fatalf("entry/exit records=%v, want %v", modes, want)
				}
			})
		}
	}
}
